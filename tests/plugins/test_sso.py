#!/usr/bin/env python
import unittest

from mock import Mock, call
import plugins.sso
from plugins import SSOUnprotected


class PluginNewInstanceTagTestCase(unittest.TestCase):
    def setUp(self):
        self.plugin = SSOUnprotected()
        self.assertEqual(self.plugin.plugin_name, 'sso_unprotected')

    def test_run(self, *mocks):
        eddaclient = Mock()
        eddaclient._since = 500

        def ret_list(args):
            return [
                {'name': 'info.prezi.com', 'instanceId': 'a', 'launchTime': 400, "resourceRecords": [{"value": "127.0.0.2"}]},
                {'name': 'info1.prezi.com', 'instanceId': 'b', 'launchTime': 600, "resourceRecords": [{"value": "127.0.0.2"}]},
            ]

        def public_ip(args):
            return [
                {'imageId': 'ami-1', 'publicIpAddress': 'a', 'launchTime': 400,
                 "resourceRecords": [{"value": "127.0.0.1.prezi.com"}]},
                {'imageId': 'ami-2', 'publicIpAddress': 'b', 'launchTime': 600,
                 "resourceRecords": [{"value": "127.0.0.2"}]},
                {'imageId': 'ami-3', 'publicIpAddress': 'c', 'launchTime': 800,
                 "resourceRecords": [{"value": "127.0.0.3.prezi.com"}, {"value": "127.0.0.4"}]},
            ]

        def page_redirects_mock(location):
            if location == "http://info.prezi.com":
                code = 200
                return SSOUnprotected.UNPROTECTED
            if location == "https://info.prezi.com":
                code = 302
                return SSOUnprotected.GODAUTH_URL + "https://info.prezi.com"
            if location == "http://info1.prezi.com":
                code = 302
                return "https://info1.prezi.com"
            if location == "https://info1.prezi.com":
                code = 302
                return SSOUnprotected.SSO_URL + "https://info1.prezi.com"

        plugins.sso.page_redirects = page_redirects_mock

        m = Mock()
        m.query = Mock(side_effect=ret_list)
        m1 = Mock()
        m1.query = Mock(side_effect=public_ip)
        eddaclient.clean = Mock(return_value=m)
        eddaclient.soft_clean = Mock(return_value=m1)

        self.plugin.init(eddaclient, {}, {})

        # run the tested method
        result = self.plugin.run()
        result = list(result)
        self.assertEqual(1, len(result))
        result = result[0]
        self.assertEqual("This domain (http://info.prezi.com) is neither behind SSO nor GODAUTH", result["details"])
        self.assertEqual("http://info.prezi.com", result["id"])

        m.query.assert_has_calls([call('/api/v2/aws/hostedRecords;_expand')])


def main():
    unittest.main()


if __name__ == '__main__':
    main()
