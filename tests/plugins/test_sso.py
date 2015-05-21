#!/usr/bin/env python
import unittest

from mock import Mock, call
from httpretty import HTTPretty, httprettified
from plugins import SSOUnprotected, SecurityHeaders
import plugins.sso


class PluginSsoTestCase(unittest.TestCase):
    def setUp(self):
        self.plugin = SSOUnprotected()
        self.assertEqual(self.plugin.plugin_name, 'sso_unprotected')

    @httprettified
    def test_run(self, *mocks):
        eddaclient = Mock()
        eddaclient._since = 500

        def ret_list(args):
            return [
                {'name': 'full-https.prezi.com', 'instanceId': 'a', 'launchTime': 400,
                 "resourceRecords": [{"value": "127.0.0.2"}]},
                {'name': 'godauth.prezi.com', 'instanceId': 'b', 'launchTime': 600,
                 "resourceRecords": [{"value": "127.0.0.2"}]},
                {'name': 'vuln.prezi.com', 'instanceId': 'b', 'launchTime': 600,
                 "resourceRecords": [{"value": "127.0.0.2"}]},
                {'name': 'prezi-sso.prezi.com', 'instanceId': 'b', 'launchTime': 600,
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

        HTTPretty.register_uri(HTTPretty.GET, 'http://vuln.prezi.com',
                               body='[{"title": "Test Deal"}]',
                               adding_headers={
                                   'Location': 'None'
                               },
                               status=200)
        HTTPretty.register_uri(HTTPretty.GET, 'https://godauth.prezi.com',
                               body='[{"title": "Test Deal"}]',
                               adding_headers={
                                   'Location': "https://god.com/?red=https://godauth.prezi.com"
                               },
                               status=302)
        HTTPretty.register_uri(HTTPretty.GET, 'http://full-https.prezi.com',
                               body='[{"title": "Test Deal"}]',
                               adding_headers={
                                   'Location': 'https://full-https.prezi.com'
                               },
                               status=302)
        HTTPretty.register_uri(HTTPretty.GET, 'https://prezi-sso.prezi.com',
                               body='[{"title": "Test Deal"}]',
                               adding_headers={
                                   'Location': "https://sso.com/?red=https://prezi-sso.prezi.com"
                               },
                               status=302)

        # run the tested method
        result = list(self.plugin.run())

        self.assertEqual(SSOUnprotected.SSO_URL + "https://prezi-sso.prezi.com",
                         plugins.sso.fetch_url('https://prezi-sso.prezi.com')[1]['headers']['location'])
        self.assertEqual("https://full-https.prezi.com",
                         plugins.sso.fetch_url('http://full-https.prezi.com')[1]['headers']['location'])
        self.assertEqual(SSOUnprotected.GODAUTH_URL + "https://godauth.prezi.com",
                         plugins.sso.fetch_url('https://godauth.prezi.com')[1]['headers']['location'])
        self.assertEqual(('http://bla.prezi.com', None), plugins.sso.fetch_url('http://bla.prezi.com'))
        self.assertEqual(1, len(result))
        result = result[0]
        self.assertEqual(
            ["This domain (http://vuln.prezi.com) is neither behind SSO nor GODAUTH because redirects to None"],
            result["details"])
        self.assertEqual("http://vuln.prezi.com", result["id"])

        m.query.assert_has_calls([call('/api/v2/aws/hostedRecords;_expand')])


class PluginSecurityHeadersTestCase(unittest.TestCase):
    def setUp(self):
        self.plugin = SecurityHeaders()
        self.assertEqual(self.plugin.plugin_name, 'security_headers')

    @httprettified
    def test_run(self, *mocks):
        eddaclient = Mock()
        eddaclient._since = 500

        def ret_list(args):
            return [
                {'name': 'full-https.prezi.com', 'instanceId': 'a', 'launchTime': 400,
                 "resourceRecords": [{"value": "127.0.0.2"}]},
                {'name': 'godauth.prezi.com', 'instanceId': 'b', 'launchTime': 600,
                 "resourceRecords": [{"value": "127.0.0.2"}]},
                {'name': 'vuln.prezi.com', 'instanceId': 'b', 'launchTime': 600,
                 "resourceRecords": [{"value": "127.0.0.2"}]},
                {'name': 'prezi-sso.prezi.com', 'instanceId': 'b', 'launchTime': 600,
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

        self.plugin.init(eddaclient, {}, {})

        HTTPretty.register_uri(HTTPretty.GET, 'http://vuln.prezi.com',
                               body='[{"title": "Test Deal"}]',
                               adding_headers={
                               },
                               status=200)
        HTTPretty.register_uri(HTTPretty.GET, 'https://godauth.prezi.com',
                               body='[{"title": "Test Deal"}]',
                               adding_headers={
                                   'x-frame-options': "INVALID"
                               },
                               status=200)
        HTTPretty.register_uri(HTTPretty.GET, 'http://full-https.prezi.com',
                               body='[{"title": "Test Deal"}]',
                               adding_headers={
                                   'Location': 'https://full-https.prezi.com',
                                   'X-FRAME-OPTIONS': 'DENY'
                               },
                               status=201)
        HTTPretty.register_uri(HTTPretty.GET, 'https://prezi-sso.prezi.com',
                               body='[{"title": "Test Deal"}]',
                               adding_headers={
                                   'X-FRAME-OPTIONS': 'SAMEORIGIN'
                               },
                               status=200)

        # run the tested method
        result = list(self.plugin.run())

        self.assertEqual(1, len(result))
        result = result[0]
        self.assertEqual(["This webpage (http://vuln.prezi.com) does not have X-Frame-Options header"],
                         result["details"])
        self.assertEqual("http://vuln.prezi.com", result["id"])

        m.query.assert_has_calls([call('/api/v2/aws/hostedRecords;_expand')])


def main():
    unittest.main()


if __name__ == '__main__':
    main()
