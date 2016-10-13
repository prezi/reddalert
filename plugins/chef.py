#!/usr/bin/env python

from __future__ import absolute_import

import logging
import re
import time

from IPy import IP
from chef import Search, ChefAPI
from chef.exceptions import ChefServerError


class NonChefPlugin:
    """
    Returns those EC2 instances which do not have a corresponding Chef entry based on the public IPv4 address.
    """

    def __init__(self):
        self.plugin_name = 'non_chef'
        self.logger = logging.getLogger(self.plugin_name)

    def init(self, edda_client, config, status, instance_enricher):
        self.edda_client = edda_client
        try:
            self.api = ChefAPI(config['chef_server_url'], config['client_key_file'], config['client_name'])
        except IOError:
            self.logger.exception('Failed to open config file: %s', config['client_key_file'])
            self.api = None
        self.excluded_instances = config.get('excluded_instances', [])
        self.initialize_status(status)
        self.instance_enricher = instance_enricher

    def initialize_status(self, status):
        if 'first_seen' not in status:
            status['first_seen'] = {}
        self.status = status

    def is_excluded_instance(self, tags):
        if 'elasticbeanstalk:environment-name' in tags or 'aws:cloudformation:stack-name' in tags:
            return True  # Amazon ElasticBeanstalk and CloudFormation hosts are not Chef managed

        if 'cloudbees:pse:type' in tags:
            return True  # New CI nodes

        if 'aws:elasticmapreduce:instance-group-role' in tags:
            return True  # EMR nodes

        service_name = tags.get('service_name', None) or tags.get('Name', None)
        for excluded_instance in self.excluded_instances:
            if service_name is not None and re.match(excluded_instance, service_name):
                return True
        return False

    def run(self):
        return list(self.do_run()) if self.api else []

    def get_chef_hosts(self):
        def get_public_ip(chef_node):
            if 'cloud' in chef_node.get('automatic', {}):
                return chef_node.get('automatic', {}).get('cloud', {}).get('public_ipv4')
            else:
                return chef_node.get('automatic', {}).get('ipaddress')

        for i in xrange(5):
            try:
                search_result = Search('node', rows=10000, api=self.api)

                if search_result:
                    return {get_public_ip(node): node for node in search_result if
                            get_public_ip(node) and IP(get_public_ip(node)).iptype() != 'PRIVATE'}
            except ChefServerError:
                time.sleep(5)

    def do_run(self):
        def _create_alert(plugin_name, alert_id, details):
            return {
                "plugin_name": plugin_name,
                "id": alert_id,
                "details": [details]
            }

        def _enrich_with_chef(chef_node):
            return {
                'chef_node_name': chef_node.get('name'),
                'hostname': chef_node['automatic'].get('machinename'),
                'fqdn': chef_node['automatic'].get('fqdn'),
                'platform': chef_node['automatic'].get('platform'),
                'operating_system': chef_node['automatic'].get('os'),
                'operating_system_version': chef_node['automatic'].get('os_version'),
            }

        # NOTE! an instance has 3 hours to register itself to chef!
        aws_to_chef_delay = 3 * 60 * 60 * 1000
        since = self.edda_client._since or 0
        until = self.edda_client._until or (since + 30 * 60 * 3600)
        check_since = since - aws_to_chef_delay
        check_until = until - aws_to_chef_delay

        chef_hosts = self.get_chef_hosts()

        if not chef_hosts:
            self.logger.warning('No chef hosts were found.')
            return

        # handle EC2 instances first
        ec2_instances = self.edda_client.soft_clean().query("/api/v2/view/instances;_expand")
        for machine in ec2_instances:
            enriched_instance = self.instance_enricher.report(machine)

            instance_id = enriched_instance['instanceId']
            launch_time = enriched_instance['started']
            tags = enriched_instance['tags']
            public_ip_address = enriched_instance['publicIpAddress']
            alert_id = "%s-%s" % (
                enriched_instance.get('keyName', enriched_instance['instanceId']),
                enriched_instance.get("service_type", "unknown_service"))

            if not self.is_excluded_instance(tags) and \
                    public_ip_address and public_ip_address != 'null':

                # found a not excluded machine
                if public_ip_address not in chef_hosts \
                        and check_since <= launch_time <= check_until and instance_id not in self.status['first_seen']:

                    # found a non-chef managed host which has not been seen before
                    self.status['first_seen'][instance_id] = launch_time
                    yield _create_alert(self.plugin_name, alert_id, enriched_instance)
                elif public_ip_address in chef_hosts:
                    # found a chef managed EC2 host, create an event so we can run conformity checks on it
                    chef_node = chef_hosts[public_ip_address]
                    enriched_instance.update(_enrich_with_chef(chef_node))
                    yield _create_alert('chef_managed', alert_id, enriched_instance)

        # handle non-ec2 chef hosts
        ec2_public_ips = [m['publicIpAddress'] for m in ec2_instances]
        for public_ip, chef_node in chef_hosts.iteritems():
            if public_ip not in ec2_public_ips and chef_node['automatic'].get('cloud', {}).get('provider') != 'ec2':
                # found a chef managed non-EC2 host, create an event so we can run conformity checks on it
                chef_details = _enrich_with_chef(chef_node)
                chef_details['publicIpAddress'] = public_ip

                yield _create_alert('chef_managed', chef_details['chef_node_name'], chef_details)
