#!/usr/bin/env python

import logging
import random
import re

import boto
from boto.exception import S3ResponseError
from boto.s3.connection import S3Connection
from boto.s3.key import Key


if not boto.config.has_section('Boto'):
    boto.config.add_section('Boto')
    boto.config.set('Boto', 'http_socket_timeout', '10')


class S3AclPlugin:
    def __init__(self):
        self.plugin_name = 's3acl'
        self.logger = logging.getLogger('s3acl')
        logging.getLogger("boto").disabled = True

    def init(self, edda_client, config, status):
        self.config = config
        self.edda_client = edda_client
        self.conn = S3Connection(self.config['user'], self.config['key'], calling_format='boto.s3.connection.ProtocolIndependentOrdinaryCallingFormat')
        self.p = config['visit_probability'] if 'visit_probability' in config else 0.1
        self.maxdir = config['visit_max'] if 'visit_max' in config else 5
        self.excluded_buckets = self.init_cache_from_list_in_config('excluded_buckets')
        self.excluded_keys = self.init_cache_from_list_in_config('excluded_keys')
        self.allowed = config['allowed'] if 'allowed' in config else []
        self.allowed_specific = config['allowed_specific'] if 'allowed_specific' in config else {}

    def init_cache_from_list_in_config(self, cache_name):
        return list(re.compile(rule_item) for rule_item in self.config[cache_name]) if cache_name in self.config else []

    def run(self):
        return list(self.do_run(self.conn))

    def get_region_aware_buckets(self, buckets):
        for bucket in buckets:
            try:
                location = bucket.get_location()
                if not location:
                    location = 'us-east-1'
                elif location == 'EU':
                    location = 'eu-west-1'
                conn = boto.s3.connect_to_region(location,
                                                 aws_access_key_id=self.config['user'],
                                                 aws_secret_access_key=self.config['key'],
                                                 calling_format='boto.s3.connection.ProtocolIndependentOrdinaryCallingFormat')

                yield conn.get_bucket(bucket.name)
            except S3ResponseError as e:
                if e.status != 404:
                    self.logger.exception("Failed to get bucket location for %s", bucket.name)

    def do_run(self, conn):
        buckets = list(self.filter_excluded_buckets(self.get_region_aware_buckets(conn.get_all_buckets())))

        for b in self.sample_population(buckets):
            bucket_alerts = self.suspicious_bucket_grants(b)
            if bucket_alerts:
                yield {
                    "plugin_name": self.plugin_name,
                    "id": "%s" % (b.name),
                    "url": "https://s3.amazonaws.com/%s" % (b.name),
                    "details": bucket_alerts
                }
            keys = self.filter_excluded_keys(self.traverse_bucket(b, ""))
            for k in keys:
                object_alerts = self.suspicious_object_grants(k)
                if object_alerts:
                    yield {
                        "plugin_name": self.plugin_name,
                        "id": "%s:%s" % (k.bucket.name, k.name),
                        "url": "https://s3.amazonaws.com/%s/%s" % (k.bucket.name, k.name),
                        "details": object_alerts
                    }

    def filter_excluded_buckets(self, buckets):
        return [bs for bs in buckets if not any(regex.match(bs.name) for regex in self.excluded_buckets)]

    def filter_excluded_keys(self, keys):
        return [key for key in keys if
                not any(regex.match('%s:%s' % (key.bucket.name, key.name)) for regex in self.excluded_keys)]

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
            self.logger.exception("S3 error: %s:%s %s", b.name, prefix, e.message)
            return []

    def sample_population(self, population, offset=0):
        pnl = len(population)
        k = int(min(max(1, self.maxdir - offset), max(1, pnl * self.p)))
        return [] if pnl == 0 else random.sample(population, k)

    def suspicious_grants(self, acp, bucket_name):
        grants = acp.acl.grants if acp is not None else []
        allowed = list(self.allowed)

        if bucket_name in self.allowed_specific:
            allowed.extend(self.allowed_specific[bucket_name])

        return ["%s %s" % (g.id or g.uri or 'Everyone', g.permission) for g in grants if self.is_suspicious(g, allowed)]

    def suspicious_object_grants(self, key):
        try:
            acp = key.get_acl()
            return self.suspicious_grants(acp, key.bucket.name)
        except S3ResponseError as e:
            if e.error_code != 'NoSuchKey':
                self.logger.exception("ACL fetching error: %s %s %s", key.name, e.message, e.error_code)
            return []

    def suspicious_bucket_grants(self, bucket):
        try:
            acp = bucket.get_acl()
            return self.suspicious_grants(acp, bucket.name)
        except S3ResponseError as e:
            self.logger.exception("ACL fetching error: %s %s %s", bucket.name, e.message, e.error_code)
            return []

    def is_suspicious(self, grant, allowed):
        actual_op = grant.permission
        if grant.type == u'Group':
            actual_group_id = grant.uri
            actual_user_id = None
        else:
            actual_group_id = None
            actual_user_id = grant.id if grant.id is not None else '*'

        for allowed_rule in allowed:
            allowed_user_id = allowed_rule.get('uid')
            allowed_group_id = allowed_rule.get('gid')
            allowed_op = allowed_rule['op']

            is_allowed_user = (False if actual_user_id is None else actual_user_id == allowed_user_id)
            is_allowed_group = (False if actual_group_id is None else actual_group_id == allowed_group_id)
            is_allowed_op = (actual_op == allowed_op)

            if is_allowed_op and (is_allowed_user or is_allowed_group):
                return False
        return True
