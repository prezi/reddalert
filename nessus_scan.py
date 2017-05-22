from api.instanceenricher import InstanceEnricher
from reddalert import Reddalert


if __name__ == '__main__':
    import argparse
    import logging
    import time
    import random
    import sys
    import boto.sqs
    import json
    import itertools
    from api import EddaClient


    parser = argparse.ArgumentParser(description='Runs tests against AWS configuration')
    parser.add_argument('--configfile', '-c', default='etc/configfile.json', help='Configuration file')
    parser.add_argument('--policy-id', '-p', help='Nessus policy id used for scanning')
    parser.add_argument('--scan-name', help='Name of the created Nessus scan')
    parser.add_argument('--service-type', '-t', help='Service type to scan')
    parser.add_argument('--random-service-types', help='Number of random service types to scan')
    parser.add_argument('--instances', '-n', default='1', help='Number of (random) instances to scan (all|<number>)')
    parser.add_argument('--region', default='us-east-1', help='Region of output SQS queue')
    parser.add_argument('--queue-name', default='sccengine-prod', help='Name of output SQS queue')
    # hack to avoid race condition within EDDA: it's possible instances are synced while eg security groups aren't.
    parser.add_argument('--until', '-u', default=int(time.time()) * 1000 - 5 * 60 * 1000, help='Until, epoch in ms')
    parser.add_argument('--edda', '-e', help='Edda base URL')
    parser.add_argument('--sentry', default=None, help='Sentry url with user:pass (optional)')
    parser.add_argument('--silent', '-l', action="count", help='Supress log messages lower than warning')
    args = parser.parse_args()

    root_logger = logging.getLogger()
    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s %(processName)-10s %(name)s %(levelname)-8s %(message)s')
    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)

    # Setup logger output
    root_logger.addHandler(ch)

    # Supress logging
    if args.silent:
        root_logger.setLevel(logging.WARNING)
    else:
        root_logger.setLevel(logging.DEBUG)

    root_logger.info('Called with %s', args)

    if args.sentry:
        from raven import Client
        from raven.handlers.logging import SentryHandler


        client = Client(args.sentry)
        handler = SentryHandler(client)
        handler.setLevel(logging.WARNING)
        root_logger.addHandler(handler)

    # Load configuration:
    config = Reddalert.load_json(args.configfile, root_logger)
    # root_logger.debug('Config: %s' % config)

    # Check arguments
    if not (args.policy_id and args.scan_name):
        root_logger.critical('Missing policy-id or scan-name argument.')
        sys.exit()

    # Setup EDDA client
    edda_url = Reddalert.get_config('edda', config, args.edda)
    edda_client = EddaClient(edda_url).until(args.until)
    instance_enricher = InstanceEnricher(edda_client)
    instance_enricher.initialize_caches()

    instances = edda_client.query("/api/v2/view/instances;_expand")
    enriched_instances = [instance_enricher.report(instance) for instance in instances]
    grouped_by_service_type = itertools.groupby(sorted(enriched_instances, key=lambda i: i['service_type']),
                                                key=lambda i: i['service_type'])
    service_types = []
    for k, g in grouped_by_service_type:
        service_types.append(list(g))  # Store group iterator as a list

    # print 'service_types', service_types
    if args.service_type:
        instance_candidates = [instance for instance in enriched_instances if
                               instance.get('service_type') == args.service_type]
        count = len(instance_candidates) if args.instances == 'all' else min(int(args.instances),
                                                                             len(instance_candidates))
        filtered_instances = [instance_candidates[i] for i in random.sample(xrange(len(instance_candidates)), count)]
        root_logger.debug('Got service type, filtered instances: %s' % json.dumps(filtered_instances, indent=4))
    elif args.random_service_types:
        count = min(int(args.random_service_types), len(service_types))
        chosen_service_types = [service_types[i] for i in random.sample(xrange(len(service_types)), count)]

        # print 'chosen_service_types', chosen_service_types
        filtered_instances = [random.choice(instances) for instances in chosen_service_types]

        root_logger.debug('Got random service types, filtered instances: %s' % json.dumps(filtered_instances, indent=4))
    else:
        filtered_instances = instances

    conn = boto.sqs.connect_to_region(args.region, aws_access_key_id=config['plugin.s3acl']['user'],
                                      aws_secret_access_key=config['plugin.s3acl']['key'])
    sqs_queue = conn.get_queue(args.queue_name)
    sqs_queue.set_message_class(boto.sqs.message.RawMessage)

    messages_to_send = []

    for enriched_instance in filtered_instances:
        root_logger.debug('Enriched instance: %s', json.dumps(enriched_instance, indent=4))

        target_ip = enriched_instance.get("privateIpAddress", enriched_instance.get("publicIpAddress"))
        open_ports = enriched_instance.get("open_ports", [])
        target_ports = [int(p.get("port")) for p in open_ports if
                        p.get("range") == "0.0.0.0/0" and int(p.get("port") or 0) > 0]
        target_ports.sort()

        if target_ip and target_ports:
            messages_to_send.append({"type": "nessus_scan",
                                     "targets": [target_ip],
                                     "nessus_ports": ",".join(str(p) for p in target_ports),
                                     "policy_id": args.policy_id,
                                     "scan_name": "%s %s %s" % (
                                         args.scan_name, enriched_instance.get("service_type"), target_ports)})

        target_elbs = enriched_instance.get("elbs", []) or []
        for elb in target_elbs:
            target_host = elb.get("DNSName")
            target_ports = elb.get("ports", [])
            target_ports.sort(key=int)
            if target_host and target_ports:
                messages_to_send.append({"type": "nessus_scan",
                                         "targets": [target_host],
                                         "nessus_ports": ",".join(str(p) for p in target_ports),
                                         "policy_id": args.policy_id,
                                         "scan_name": "%s %s %s - ELB" % (
                                             args.scan_name, enriched_instance.get("service_type"), target_ports)})

    for event in messages_to_send:
        root_logger.info('Sending event to SQS queue: %s' % event)
        message = boto.sqs.message.RawMessage()
        message.set_body(json.dumps(event))
        sqs_queue.write(message)
