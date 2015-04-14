#!/usr/bin/env python
import unittest

from mock import Mock, call
from httpretty import HTTPretty, httprettified
from plugins import SSOUnprotected


class PluginNewInstanceTagTestCase(unittest.TestCase):
    def setUp(self):
        self.plugin = SSOUnprotected()
        self.assertEqual(self.plugin.plugin_name, 'sso_unprotected')

    @httprettified
    def test_run(self, *mocks):
        eddaclient = Mock()
        eddaclient._since = 500

        def ret_list(args):
            return [
                {'name': 'info.prezi.com', 'instanceId': 'a', 'launchTime': 400,
                 "resourceRecords": [{"value": "127.0.0.2"}]},
                {'name': 'info1.prezi.com', 'instanceId': 'b', 'launchTime': 600,
                 "resourceRecords": [{"value": "127.0.0.2"}]},
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

        m = Mock()
        m.query = Mock(side_effect=ret_list)
        m1 = Mock()
        m1.query = Mock(side_effect=public_ip)
        eddaclient.clean = Mock(return_value=m)
        eddaclient.soft_clean = Mock(return_value=m1)

        self.plugin.init(eddaclient, {'godauth_url': 'https://god.com/?red=', 'sso_url': 'https://sso.com/?red='}, {})

        HTTPretty.register_uri(HTTPretty.GET, 'http://info.prezi.com',
                               body='[{"title": "Test Deal"}]',
                               adding_headers={
                                   'Location': 'None'
                               },
                               status=200)
        HTTPretty.register_uri(HTTPretty.GET, 'https://info.prezi.com',
                               body='[{"title": "Test Deal"}]',
                               adding_headers={
                                   'Location': SSOUnprotected.GODAUTH_URL + "https://info.prezi.com"
                               },
                               status=302)
        HTTPretty.register_uri(HTTPretty.GET, 'http://info1.prezi.com',
                               body='[{"title": "Test Deal"}]',
                               adding_headers={
                                   'Location': 'https://info1.prezi.com'
                               },
                               status=302)
        HTTPretty.register_uri(HTTPretty.GET, 'https://info1.prezi.com',
                               body='[{"title": "Test Deal"}]',
                               adding_headers={
                                   'Location': SSOUnprotected.SSO_URL + "https://info1.prezi.com"
                               },
                               status=302)

        # run the tested method
        result = self.plugin.run()
        result = list(result)
        self.assertEqual(1, len(result))
        result = result[0]
        self.assertEqual(["This domain (http://info.prezi.com) is neither behind SSO nor GODAUTH"], result["details"])
        self.assertEqual("http://info.prezi.com", result["id"])

        m.query.assert_has_calls([call('/api/v2/aws/hostedRecords;_expand')])


def main():
    unittest.main()


if __name__ == '__main__':
    main()
