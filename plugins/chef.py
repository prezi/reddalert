#!/usr/bin/env python

from __future__ import absolute_import
import logging
from chef import Search, ChefAPI


class NonChefPlugin:
    '''
    Returns those EC2 instances which do not have a corresponding Chef entry based on the public IPv4 address.
    '''

    def __init__(self):
        self.plugin_name = 'non_chef'
        self.logger = logging.getLogger('non_chef')

    def init(self, edda_client, config, status):
        self.edda_client = edda_client
        self.api = ChefAPI(config['chef_server_url'], config['client_key_file'], config['client_name'])
        self.excluded_instances = config.get('excluded_instances', [])
        self.initialize_status(status)

    def initialize_status(self, status):
        if 'first_seen' not in status:
            status['first_seen'] = {}
        self.status = status

    def run(self):
        return list(self.do_run())

    def do_run(self):
        since = self.edda_client._since or 0
        chef_hosts = {row['automatic']['cloud']['public_ipv4']: row['name']
                      for row in Search('node', 'ec2:*', rows=1000, api=self.api)
                      if 'cloud' in row.get('automatic', {}) and    # only store EC2 instances
                         'public_ipv4' in row['automatic']['cloud']   # which have public IP address
                      }

        # print chef_hosts

        for machine in self.edda_client.clean().query("/api/v2/view/instances;_expand"):
            launchTime = int(machine.get("launchTime", 0))

            # convert list of tags to a more readable dict
            tags = {tag['key']: tag['value'] for tag in machine.get('tags', []) if 'key' in tag and 'value' in tag}
            if machine['publicIpAddress'] not in chef_hosts and launchTime >= since and \
                    tags.get('service_name', None) not in self.excluded_instances and \
                    machine['instanceId'] not in self.status['first_seen']:
                # found a non-chef managed host which has not been seen before and which is not excluded
                self.status['first_seen'][machine['instanceId']] = launchTime
                yield {
                    "plugin_name": self.plugin_name,
                    "id": "%s (%s / %s)" % (machine['instanceId'], machine['publicIpAddress'], machine['privateIpAddress']),
                    "details": [{'tags': tags, 'keyName': machine.get('keyName', None),
                                'securityGroups': machine.get('securityGroups', [])}]
                }
