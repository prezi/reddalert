#!/usr/bin/env python

from __future__ import absolute_import
import logging
from chef import Search, ChefAPI

class Route53Unknown:

    def __init__(self):
        self.plugin_name = 'route53unknown'
        self.logger = logging.getLogger(self.plugin_name)

    def init(self, edda_client, config, status):
        self.edda_client = edda_client
        self.config = config
        self.status = status
        self.chef_api = self._initialize_chef_api()
        self._initialize_status()

    def _initialize_chef_api(self):
        try:
            return ChefAPI(self.config['chef_server_url'], self.config['client_key_file'], self.config['client_name'])
        except:
            self.logger.exception('Failed to open config file: %s', self.config['client_key_file'])
            return None

    def _initialize_status(self):
        if 'known' not in self.status:
            self.status['known'] = []

    def run(self):
        self.registered_ips = self.load_known_ips()
        route53_zone = self.config.get("zone")
        zone_selector = ";zone.name=%s" % route53_zone if route53_zone else ""
        route53_entries_raw = self.edda_client.clean().query("/api/v2/aws/hostedRecords%s;_expand" % zone_selector)
        route53_entries_dict = {e.get("name"): e for e in route53_entries_raw} # make it distinct
        route53_entries = route53_entries_dict.values()
        external_entries = [e for e in route53_entries if e.get("type") in ("A", "CNAME") and self.is_external(e)]
        alerts = []
        for e in external_entries:
            records = [r.get("value") for r in e.get("resourceRecords")]
            for r in records:
                if self.is_ip_unknown(r) and self.is_cname_unknown(r):
                    alerts.append((e.get("name", "<unknown>"), r))
        alerts_filtered = [a for a in alerts if ("%s-%s" % a) not in self.status['known']]
        self.status['known'] = ["%s-%s" % a for a in alerts]
        for a in alerts_filtered:
            yield {
                "plugin_name": self.plugin_name,
                "id": a[0],
                "details": [a[1]]
            }

    def is_ip_unknown(self, ip):
        return ip not in self.registered_ips

    def is_cname_unknown(self, record):
        if any(record.endswith(le) for le in self.config.get("legit_domains", [])):
            return False

        if record.startswith("ec2-"):
            ipaddr = record[4:record.find(".compute")].replace("-", ".")
            return self.is_ip_unknown(ipaddr)

        return True

    def is_external(self, entry):
        aliases = [r.get("value") for r in entry.get("resourceRecords")]
        return any(self.is_ip_unknown(r) and self.is_cname_unknown(r) for r in aliases)

    def load_known_ips(self):
        self.logger.debug("Loading public IP list from chef")
        nodes = list(Search('node', '*:*', rows=2000, api=self.chef_api))
        cloud_ips = [node.get("automatic", {}).get("cloud", {}).get("public_ips", []) for node in nodes]
        phy_ifaces = sum([node["automatic"].get("network", {}).get("interfaces", {}).values() for node in nodes], [])
        phy_ips = [i.get("addresses", {}).keys() for i in phy_ifaces]
        self.logger.debug("Loading public IP list from AWS")
        aws_machines = self.edda_client.soft_clean().query("/api/v2/view/instances;_expand")
        aws_ips = [m.get("publicIpAddress") for m in aws_machines]
        return set(sum(cloud_ips, []) + sum(phy_ips, []) + aws_ips) #flatten