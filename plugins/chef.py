#!/usr/bin/env python

from __future__ import absolute_import
import logging
import re
from chef import Search, ChefAPI


class NonChefPlugin:
    '''
    Returns those EC2 instances which do not have a corresponding Chef entry based on the public IPv4 address.
    '''

    def __init__(self):
        self.plugin_name = 'non_chef'
        self.logger = logging.getLogger('non_chef')

    def init(self, edda_client, config, status, instance_enricher):
        self.edda_client = edda_client
        try:
            self.api = ChefAPI(config['chef_server_url'], config['client_key_file'], config['client_name'])
        except:
            self.logger.exception('Failed to open config file: %s', config['client_key_file'])
            self.api = None
        self.excluded_instances = config.get('excluded_instances', [])
        self.initialize_status(status)
        self.instance_enricher = instance_enricher

    def initialize_status(self, status):
        if 'first_seen' not in status:
            status['first_seen'] = {}
        self.status = status

    def is_excluded_instance(self, service_name):
        for excluded_instance in self.excluded_instances:
            if service_name is not None and re.match(excluded_instance, service_name):
                return True
        return False

    def run(self):
        return list(self.do_run()) if self.api else []

    def do_run(self):
        # NOTE! an instance has 3 hours to register itself to chef!
        aws_to_chef_delay = 3 * 60 * 60 * 1000
        since = self.edda_client._since or 0
        until = self.edda_client._until or (since + 30 * 60 * 3600)
        check_since = since - aws_to_chef_delay
        check_until = until - aws_to_chef_delay

        chef_hosts = {row['automatic']['cloud']['public_ipv4']: row['name']
                      for row in Search('node', 'ec2:*', rows=1000, api=self.api)
                      if 'cloud' in row.get('automatic', {}) and    # only store EC2 instances
                         'public_ipv4' in row['automatic']['cloud']   # which have public IP address
                      }

        # print chef_hosts
        for machine in self.edda_client.soft_clean().query("/api/v2/view/instances;_expand;_at=%s"):
            launch_time = int(machine.get("launchTime", 0))

            # convert list of tags to a more readable dict
            tags = {tag['key']: tag['value'] for tag in machine.get('tags', []) if 'key' in tag and 'value' in tag}
            if machine['publicIpAddress'] not in chef_hosts and check_since <= launch_time <= check_until and \
                    not self.is_excluded_instance(tags.get('service_name', None) or tags.get('Name', None)) and \
                    machine['instanceId'] not in self.status['first_seen']:
                # found a non-chef managed host which has not been seen before and which is not excluded
                self.status['first_seen'][machine['instanceId']] = launch_time
                extra_details = {
                    'tags': tags,
                    'keyName': machine.get('keyName', None),
                    'securityGroups': machine.get('securityGroups', [])
                }
                details = self.instance_enricher.report(machine, extra=extra_details)
                yield {
                    "plugin_name": self.plugin_name,
                    "id": "%s-%s" % (machine.get('keyName', machine['instanceId']), machine.get("service_type", "unknown_service")),
                    "details": [details]
                }
