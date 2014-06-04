#!/usr/bin/env python

import logging
import random

from boto.s3.key import Key
from boto.s3.connection import S3Connection, OrdinaryCallingFormat
from boto.exception import S3ResponseError


class S3AclPlugin:

    def __init__(self):
        self.plugin_name = 's3acl'
        self.logger = logging.getLogger('s3acl')
        logging.getLogger("boto").disabled = True

    def init(self, edda_client, config, status):
        self.edda_client = edda_client
        self.conn = S3Connection(config['user'], config['key'])
        self.p = config['visit_probability'] if 'visit_probability' in config else 0.1
        self.maxdir = config['visit_max'] if 'visit_max' in config else 5
        self.excluded_buckets = config['excluded_buckets'] if 'excluded_buckets' in config else []
        self.allowed = config['allowed'] if 'allowed' in config else []
        self.allowed_specific = config['allowed_specific'] if 'allowed_specific' in config else {}

    def run(self):
        return list(self.do_run(self.conn))

    def do_run(self, conn):
        buckets = [bs for bs in conn.get_all_buckets() if bs.name not in self.excluded_buckets]

        for b in self.sample_population(buckets):
            keys = self.traverse_bucket(b, "")
            for k in keys:
                alerts = self.suspicious_grants(k)
                if alerts:
                    yield {
                        "plugin_name": self.plugin_name,
                        "id": "%s:%s" % (k.bucket.name, k.name),
                        "url": "http://s3.amazonaws.com/%s/%s" % (k.bucket.name, k.name),
                        "details": alerts
                    }

    def traverse_bucket(self, b, prefix):
        self.logger.debug("traverse_bucket('%s', '%s')" % (b.name, prefix))
        try:
            elems = list(b.list(prefix, "/"))  # we'll iterate twice
            keys = list([e for e in elems if isinstance(e, Key)])
            prefix_names = [e.name for e in elems if not isinstance(e, Key)]
            selected_prefixes = self.sample_population(prefix_names, sum(c == '/' for c in prefix))
            selected_keys = self.sample_population(keys)

            for sp in selected_prefixes:
                selected_keys.extend(self.traverse_bucket(b, sp))
            return selected_keys
        except S3ResponseError as e:
            self.logger.error("S3 error: %s:%s %s", b.name, prefix, e.message)
            return []

    def sample_population(self, population, offset=0):
        pnl = len(population)
        k = int(min(max(1, self.maxdir - offset), max(1, pnl * self.p)))
        return [] if pnl == 0 else random.sample(population, k)

    def suspicious_grants(self, key):
        try:
            acp = key.get_acl()
            grants = acp.acl.grants if acp is not None else []
            allowed = list(self.allowed)

            if key.bucket.name in self.allowed_specific:
                allowed.extend(self.allowed_specific[key.bucket.name])

            return ["%s %s" % (g.id or 'Everyone', g.permission) for g in grants if self.is_suspicious(g, allowed)]
        except S3ResponseError as e:
            self.logger.error("ACL fetching error: %s %s", key.name, e.message)
            return []

    def is_suspicious(self, grant, allowed):
        uid = grant.id if grant.id is not None else '*'
        op = grant.permission
        return not any(a['uid'] == uid and a['op'] == op for a in allowed)
