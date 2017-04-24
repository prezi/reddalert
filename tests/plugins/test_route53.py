#!/usr/bin/env python
import unittest

from mock import Mock, call, patch, MagicMock
from plugins.route53 import load_route53_entries, is_external, page_process_for_route53changed


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


class Route53ChangedDoesNotExist(unittest.TestCase):
    @patch('plugins.route53.urllib2')
    def test_run(self, mock_urllib2):
        import re
        does_not_exist_regexes = [
            re.compile(r"NoSuchBucket|NoSuchKey|NoSuchVersion"),  # NoSuch error messages from S3
            re.compile(r"[Ee]xpir(ed|y|es)"),  # expiry messages
            re.compile(r"not exists?")  # generic does not exist
        ]

        def mocked_get_location_content(location, *args, **kwargs):
            if location == "https://prezi.com/nosuch1":
                return MagicMock(read=MagicMock(side_effect=lambda: "somethingNoSuchBucketsomethingsomething"))
            if location == "https://meh.prezi.com":
                return MagicMock(read=MagicMock(side_effect=lambda: "OK, whatevs"))
            if location == "https://my404.prezi.com":
                return MagicMock(read=MagicMock(side_effect=lambda: "this page does not exist"))

        mock_urllib2.urlopen = MagicMock(side_effect=mocked_get_location_content)
        results = list(page_process_for_route53changed('https://prezi.com/nosuch1', does_not_exist_regexes))
        self.assertEquals(set(['NoSuchBucket|NoSuchKey|NoSuchVersion']), results[1]["matches"])
        results = list(page_process_for_route53changed('https://meh.prezi.com', does_not_exist_regexes))
        self.assertEquals(set([]), results[1]["matches"])
        results = list(page_process_for_route53changed('https://my404.prezi.com', does_not_exist_regexes))
        self.assertEquals(set(["not exists?"]), results[1]["matches"])


def main():
    unittest.main()


if __name__ == '__main__':
    main()
