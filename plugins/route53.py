#!/usr/bin/env python

from __future__ import absolute_import
import logging
import hashlib
import re
import urllib2
from chef import Search, ChefAPI
from multiprocessing import Pool
from IPy import IP
from functools import partial

def is_ip_unknown(ip, ip_set):
    return ip not in ip_set

def is_cname_unknown(record, ip_set, legit_domains):
    if any(record.endswith(le) for le in legit_domains):
        return False

    if record.startswith("ec2-"):
        ipaddr = record[4:record.find(".compute")].replace("-", ".")
        return is_ip_unknown(ipaddr, ip_set)

    return True

def is_external(entry, ip_set, legit_domains):
    aliases = [r.get("value") for r in entry.get("resourceRecords")]
    return any(is_ip_unknown(r, ip_set) and is_cname_unknown(r, ip_set, legit_domains) for r in aliases)

def is_ip_private(ip_addr):
    try:
        ip = IP(ip_addr)
        return ip.iptype() != 'PRIVATE'
    except:
        return False

def load_route53_entries(edda_client, zone=None):
    zone_selector = ";zone.name=%s" % zone if zone else ""
    route53_entries_raw = edda_client.clean().query("/api/v2/aws/hostedRecords%s;_expand" % zone_selector)
    route53_entries_dict = {e.get("name"): e for e in route53_entries_raw} # make it distinct
    return route53_entries_dict.values()


route53_changed_no_content_regexes = [
            re.compile(r"NoSuchBucket|NoSuchKey|NoSuchVersion"),      # NoSuch error messages from S3
            re.compile(r"[Ee]xpir(ed|y|es)"),                       # expiry messages
            re.compile(r"not exists?")                                # generic does not exist
]

def page_process_for_route53changed(location):
    try:
        if location.endswith("."):
            location = location[:-1]
        page_content = urllib2.urlopen(location, timeout=3).read()
        page_top = page_content[255:512]
        if len(page_content) <= 255:
            page_top = page_content

        matches = []
        for regex in route53_changed_no_content_regexes:
            if re.search(regex, page_content[:2048]):
                matches.append(regex.pattern)

        return location, {"hash": hashlib.sha224(page_top).hexdigest(), "matches": matches}
    except:
        return location, {"hash": "-", "matches": []}


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
        registered_ips = self.load_known_ips()
        legit_domains = self.config.get("legit_domains", [])
        route53_zone = self.config.get("zone")
        route53_entries = load_route53_entries(self.edda_client, route53_zone)
        external_entries = [e for e in route53_entries
                            if e.get("type") in ("A", "CNAME") and is_external(e, registered_ips, legit_domains)]
        alerts = []
        for e in external_entries:
            records = [r.get("value") for r in e.get("resourceRecords")]
            for r in records:
                if is_ip_private(r):
                    continue
                if is_ip_unknown(r, registered_ips) and is_cname_unknown(r, registered_ips, legit_domains):
                    alerts.append((e.get("name", "<unknown>"), r))
        alerts_filtered = [a for a in alerts if ("%s-%s" % a) not in self.status['known']]
        self.status['known'] = ["%s-%s" % a for a in alerts]
        for a in alerts_filtered:
            yield {
                "plugin_name": self.plugin_name,
                "id": a[0],
                "details": [a[1]]
            }

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


class Route53Changed:

    def __init__(self):
        self.plugin_name = 'route53changed'
        self.logger = logging.getLogger(self.plugin_name)

    def init(self, edda_client, config, status):
        self.edda_client = edda_client
        self.config = config
        self.status = status
        self._initialize_status()

    def _initialize_status(self):
        if 'hashes' not in self.status:
            self.status['hashes'] = {}

    def run(self):
        ips = self.load_aws_ips()
        legit_domains = self.config.get("legit_domains", [])
        exempts = self.config.get("exception_domains", [])
        dns_names = self.load_known_dns()
        # using bugbounty.prezi.com for testing
        not_aws = {name: entry for name, entry in dns_names.iteritems()
                   if name == "bugbounty.prezi.com." or (is_external(entry, ips, legit_domains) and name not in exempts)}
        locations_http = ["http://%s" % name for name in not_aws.keys()]
        locations_https = ["https://%s" % name for name in not_aws.keys()]
        locations = list(locations_http + locations_https)
        self.logger.info("fetching %d urls on 16 threads" % len(locations))
        hashed_items = Pool(16).map(page_process_for_route53changed, locations)
        hashes = dict(hashed_items)
        old_hashes = self.status.get("hashes", {})

        def backward_compatible_hash_compare(location, old_hashes, new_hash):
            if type(old_hashes[location]) is dict:
                # according to the new JSON schema. e.g.:
                # { "https://something.prezi.com": { "hash": "...", "matches": [ ... ] }, ... }
                return old_hashes[location]["hash"] != new_hash["hash"]
            else:
                # according to the old JSON schema, e.g.:
                # { "https://something.prezi.com": "sha224", ... }
                return old_hashes[location] != new_hash

        hash_changed_alerts = {loc: h for loc, h in hashes.iteritems() if loc not in old_hashes or backward_compatible_hash_compare(loc, old_hashes, h)}
        self.status["hashes"] = hashes
        for location, info in hash_changed_alerts.iteritems():
            dns_name = "%s." % re.search('http[s]*://(.*)', location).group(1)
            dns_entry_info = not_aws.get(dns_name,"no_dns_entry_info_found")
            yield {
                "plugin_name": self.plugin_name,
                "id": location,
                "details": ("new page (dns entry info: %s)" % str(dns_entry_info),) if location not in old_hashes else ("page changed (%s) new_hash: %s" % (str(dns_entry_info), info["hash"]),)
            }

            if len(info["matches"]) > 0:
                yield {
                    "plugin_name": self.plugin_name,
                    "id": location,
                    "details": ("location matches the following regexes: %s" % info["matches"] + "\n (S3 bucket removed or domain expired?)",)
                }

    def load_aws_ips(self):
        aws_machines = self.edda_client.soft_clean().query("/api/v2/view/instances;_expand")
        return [m.get("publicIpAddress") for m in aws_machines]

    def load_known_dns(self):
        route53_zone = self.config.get("zone")
        entries = load_route53_entries(self.edda_client, route53_zone)
        name_map = {e.get("name"): e for e in entries}
        return name_map
