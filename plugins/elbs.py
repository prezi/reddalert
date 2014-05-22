#!/usr/bin/env python


class ElasticLoadBalancerPlugin:

    def __init__(self):
        self.plugin_name = 'elbs'

    def init(self, edda_client, config, status):
        self.edda_client = edda_client
        self.status = status
        self.config = config
        self.allowed_elb_ports = config["allowed_ports"] if "allowed_ports" in config else []

    def run(self):
        return list(self.do_run())

    def do_run(self):
        elbs = self.edda_client.updateonly().query("/api/v2/aws/loadBalancers;_expand")
        for elb in elbs:
            if self.is_suspicious(elb):
                yield {
                    "plugin_name": self.plugin_name,
                    "id": elb["loadBalancerName"],
                    "details": [self.create_details(elb)]
                }

    def is_suspicious(self, elb):
        for listener in elb["listenerDescriptions"]:
            if int(listener['listener']['loadBalancerPort']) not in self.allowed_elb_ports:
                return True

        return False

    def create_details(self, elb):
        return {
            'canonicalHostedZoneName': elb['canonicalHostedZoneName'],
            'numberOfInstances': len(elb['instances']),
            'listenerDescriptions': elb['listenerDescriptions']
        }
