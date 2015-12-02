#!/usr/bin/env python

from __future__ import absolute_import
import logging
import time
import re

from chef import Search, ChefAPI
from chef.exceptions import ChefServerError


class NonChefPlugin:
    '''
    Returns those EC2 instances which do not have a corresponding Chef entry based on the public IPv4 address.
    '''

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

    def is_excluded_instance(self, service_name):
        for excluded_instance in self.excluded_instances:
            if service_name is not None and re.match(excluded_instance, service_name):
                return True
        return False

    def run(self):
        return list(self.do_run()) if self.api else []

    def get_chef_hosts(self):
        for i in xrange(5):
            try:
                search_result = Search('node', 'ec2:*', rows=2000, api=self.api)
                if search_result:
                    return {row['automatic']['cloud']['public_ipv4']: row['name']
                            for row in search_result
                            if 'cloud' in row.get('automatic', {}) and  # only store EC2 instances
                            'public_ipv4' in row['automatic']['cloud']  # which have public IP address
                            }
            except ChefServerError:
                time.sleep(5)
        return None

    def do_run(self):
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

        for machine in self.edda_client.soft_clean().query("/api/v2/view/instances;_expand"):
            launch_time = int(machine.get("launchTime", 0))

            # convert list of tags to a more readable dict
            tags = {tag['key']: tag['value'] for tag in machine.get('tags', []) if 'key' in tag and 'value' in tag}
            extra_details = {
                'tags': tags,
                'keyName': machine.get('keyName', None),
                'securityGroups': machine.get('securityGroups', [])
            }

            if not self.is_excluded_instance(tags.get('service_name', None) or tags.get('Name', None)) and \
                            machine['publicIpAddress'] != 'null' and machine['publicIpAddress'] is not None:

                # found a not excluded machine
                if machine['publicIpAddress'] not in chef_hosts and check_since <= launch_time <= check_until and \
                                machine['instanceId'] not in self.status['first_seen']:

                    # found a non-chef managed host which has not been seen before
                    self.status['first_seen'][machine['instanceId']] = launch_time

                    details = self.instance_enricher.report(machine, extra=extra_details)
                    yield {
                        "plugin_name": self.plugin_name,
                        "id": "%s-%s" % (
                            machine.get('keyName', machine['instanceId']),
                            machine.get("service_type", "unknown_service")),
                        "details": [details]
                    }
                elif machine['publicIpAddress'] in chef_hosts:

                    # found a chef managed host, create an event so we can run conformity checks on it
                    details = self.instance_enricher.report(machine, extra=extra_details)
                    yield {
                        "plugin_name": 'chef_managed',
                        "id": "%s-%s" % (
                            machine.get('keyName', machine['instanceId']),
                            machine.get("service_type", "unknown_service")),
                        "details": [details]
                    }
