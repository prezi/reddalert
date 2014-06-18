#!/usr/bin/env python
import socket
import unittest
from mock import patch, Mock, call, MagicMock

from plugins import S3AclPlugin
from boto.s3.key import Key
from boto.exception import S3ResponseError


class PluginS3AclTestCase(unittest.TestCase):

    def setUp(self):
        self.plugin = S3AclPlugin()
        self.assertEqual(self.plugin.plugin_name, 's3acl')
        self.buckets = ['bucket1', 'bucket2', 'assets', 'bucket3']

    def test_initialize(self):
        self.plugin.init(Mock(), {'user': 'bob', 'key': 'xxx'}, {})
        self.assertEqual(self.plugin.p, 0.1)
        self.assertEqual(self.plugin.maxdir, 5)
        self.assertEqual(self.plugin.excluded_buckets, [])
        self.assertEqual(self.plugin.excluded_keys, [])
        self.assertEqual(self.plugin.allowed, [])
        self.assertEqual(self.plugin.allowed_specific, {})

    @patch('random.sample', return_value=["bucket1", "bucket2"])
    def test_sample_population(self, *mocks):
        self.plugin.init(Mock(), {'user': 'bob', 'key': 'xxx'}, {})
        self.assertEqual(self.plugin.sample_population([], 2), [])
        self.plugin.p = 30
        self.assertEqual(self.plugin.sample_population(self.buckets, 3), ["bucket1", "bucket2"])

    def test_suspicious_grants(self, *mocks):
        with patch('boto.s3.key.Key') as MockClass:
            key = MockClass.return_value
            key.bucket.name = 'allowed_bucket'

            acp = Mock()
            acp.acl.grants = [Mock(), Mock()]
            acp.acl.grants[0].id = 'id'
            acp.acl.grants[0].permission = 'permission'
            acp.acl.grants[1].id = 'id2'
            acp.acl.grants[1].permission = 'permission2'

            key.get_acl = Mock(return_value=acp)
            self.plugin.init(Mock(), {'user': 'bob', 'key': 'xxx', 'allowed_specific': {
                             'allowed_bucket': [{'uid': 'id2', 'op': 'permission2'}]}}, {})
            self.assertEqual(self.plugin.suspicious_grants(key), ['id permission'])

    def test_traverse_bucket(self, *mocks):

        def ret_sample(population, offset=1):
            if population and offset == 1:
                # sample keys
                return [population[0]]
            else:
                return population

        with patch('plugins.S3AclPlugin.sample_population', side_effect=ret_sample) as MockClass:
            bucket = Mock()
            bucket.name = 'bucket1'
            prefix = Mock()
            prefix.name = 'prefix'
            key = Mock(Key)
            key.name = 'key1'
            key2 = Mock(Key)
            key2.name = 'key2'

            def ret_list(pref, slash):
                if pref == '':
                    return [key, prefix, key2]
                else:
                    return []

            bucket.list.side_effect = ret_list

            self.plugin.init(Mock(), {'user': 'bob', 'key': 'xxx'}, {})
            self.assertEqual(self.plugin.traverse_bucket(bucket, ''), [key])

    @patch('plugins.S3AclPlugin.sample_population', return_value=[Mock()])
    def test_do_run(self, *mocks):

        key1 = Mock(Key)
        key1.name = 'key1'
        key1.bucket = Mock()
        key1.bucket.name = 'bucket1'
        key2 = Mock(Key)
        key2.name = 'key2'
        key2.bucket = Mock()
        key2.bucket.name = 'bucket1'

        def ret_keys(key):
            if key == key1:
                return ['id permission']
            return []

        with patch('plugins.S3AclPlugin.traverse_bucket', return_value=[key1, key2]) as MockClass:
            with patch('plugins.S3AclPlugin.suspicious_grants', side_effect=ret_keys):

                self.plugin.init(Mock(), {'user': 'bob', 'key': 'xxx'}, {})
                # run the tested method
                self.assertEqual(list(self.plugin.do_run(MagicMock())), [
                                 {'details': ['id permission'], 'id': 'bucket1:key1',
                                  'url': 'http://s3.amazonaws.com/bucket1/key1', 'plugin_name': 's3acl'}])

    def test_survive_s3error_traverse(self):
        bucket = Mock()
        bucket.list = Mock(side_effect=S3ResponseError(404, 'Not found', ''))
        self.plugin.init(Mock(), {'user': 'bob', 'key': 'xxx'}, {})

        r = self.plugin.traverse_bucket(bucket, '')

        self.assertEqual([], r)

    def test_survive_s3error_suspicious(self):
        k = Mock()
        k.get_acl = Mock(side_effect=S3ResponseError(404, 'Not found', ''))
        self.plugin.init(Mock(), {'user': 'bob', 'key': 'xxx'}, {})

        r = self.plugin.suspicious_grants(k)

        self.assertEqual([], r)

    def test_filter_excluded_buckets(self):
        bucket1 = Mock(Key)
        bucket1.name = 'bucket1'
        bucket2 = Mock(Key)
        bucket2.name = 'bucket2'
        bucket3 = Mock(Key)
        bucket3.name = 'bucket3'

        self.plugin.init(Mock(), {'user': 'bob', 'key': 'xxx', 'excluded_buckets': ['bucket[13]+', 'shouldntmatter.*']}, {})
        r = self.plugin.filter_excluded_buckets([bucket1, bucket2, bucket3])
        self.assertEqual([bucket2], r)

    def test_filter_excluded_keys(self):
        key1 = Mock(Key)
        key1.name = 'key1'
        key1.bucket = Mock()
        key1.bucket.name = 'bucket1'
        key2 = Mock(Key)
        key2.name = 'key2'
        key2.bucket = Mock()
        key2.bucket.name = 'bucket1'

        self.plugin.init(Mock(), {'user': 'bob', 'key': 'xxx', 'excluded_keys': ['^bucket[13]:.*2$', 'shouldntmatter.*']}, {})
        r = self.plugin.filter_excluded_keys([key1, key2])
        self.assertEqual([key1], r)

def main():
    unittest.main()

if __name__ == '__main__':
    main()
