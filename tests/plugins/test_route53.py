#!/usr/bin/env python
import unittest

from mock import Mock, call
from plugins.route53 import load_route53_entries, is_external


class LoadRoute53EntriesTestCase(unittest.TestCase):
    def test_run(self, *mocks):
        eddaclient = Mock()
        eddaclient._since = 500

        def ret_list(args):
            return [
                {'name': 'info.prezi.com', 'instanceId': 'a', 'launchTime': 400},
                {'name': 'info.prezi.com', 'instanceId': 'a', 'launchTime': 400},
                {'name': 'info.prezi.com', 'instanceId': 'a', 'launchTime': 400},
                {'name': 'info1.prezi.com', 'instanceId': 'b', 'launchTime': 600},
                {'name': 'info1.prezi.com', 'instanceId': 'b', 'launchTime': 600}
            ]

        m = Mock()
        m.query = Mock(side_effect=ret_list)
        eddaclient.clean = Mock(return_value=m)

        self.assertEqual([{'name': 'info.prezi.com', 'instanceId': 'a', 'launchTime': 400},
                          {'name': 'info1.prezi.com', 'instanceId': 'b', 'launchTime': 600}],
                         load_route53_entries(eddaclient))
        m.query.assert_has_calls([call('/api/v2/aws/hostedRecords;_expand')])


class IsExternalTestCase(unittest.TestCase):
    def test_run(self, *mocks):
        values = [
            {'imageId': 'ami-1', 'instanceId': 'a', 'launchTime': 400,
             "resourceRecords": [{"value": "127.0.0.1.prezi.com"}]},
            {'imageId': 'ami-2', 'instanceId': 'b', 'launchTime': 600, "resourceRecords": [{"value": "127.0.0.2"}]},
            {'imageId': 'ami-3', 'instanceId': 'c', 'launchTime': 800,
             "resourceRecords": [{"value": "127.0.0.3.prezi.com"}, {"value": "127.0.0.4"}]},
        ]

        ip_set = ['127.0.0.1.prezi.com', '127.0.0.3.prezi.com']
        domains_set = ['prezi.com']
        result = [v for v in values if is_external(v, ip_set, domains_set)]

        # run the tested method
        self.assertEqual(2, len(result))
        result = result[0]
        self.assertEqual("ami-2", result["imageId"])
        self.assertEqual(1, len(result["resourceRecords"]))


def main():
    unittest.main()


if __name__ == '__main__':
    main()
