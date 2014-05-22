#!/usr/bin/env python
import os
import unittest
from mock import patch, Mock, call

from plugins import ElasticLoadBalancerPlugin


class PluginElbTestCase(unittest.TestCase):

    def setUp(self):
        self.plugin = ElasticLoadBalancerPlugin()
        self.assertEqual(self.plugin.plugin_name, 'elbs')
        self.config = {"allowed_ports": [80, 443]}

    def test_is_suspicious(self):
        self.plugin.init(Mock(), self.config, {})
        elb = {"listenerDescriptions": [
               {"listener": {"SSLCertificateId": None, "instancePort": 8443, "instanceProtocol":
                             "TCP", "loadBalancerPort": 22, "protocol": "TCP"}, "policyNames": []}
               ]}

        self.assertTrue(self.plugin.is_suspicious(elb))

        elb = {"listenerDescriptions": [
               {"listener": {"SSLCertificateId": None, "instancePort": 8443, "instanceProtocol":
                             "TCP", "loadBalancerPort": 443, "protocol": "TCP"}, "policyNames": []}
               ]}
        self.assertFalse(self.plugin.is_suspicious(elb))

    def test_run(self, *mocks):

        eddaclient = Mock()

        def ret_list(args):
            return [{'loadBalancerName': 'test-elb', 'canonicalHostedZoneName': 'test-hostname',
                     'instances': [{}, {}], "listenerDescriptions": [
                         {"listener": {
                          "SSLCertificateId": None, "instancePort": 8443, "instanceProtocol":
                          "TCP", "loadBalancerPort": 22, "protocol": "TCP"}, "policyNames": []
                          }
                     ]},
                    {'loadBalancerName': 'production-elb', 'canonicalHostedZoneName': 'production-hostname',
                     'instances': [{}, {}, {}, {}, {}], "listenerDescriptions": [
                         {"listener": {
                          "SSLCertificateId": None, "instancePort": 8443, "instanceProtocol":
                          "TCP", "loadBalancerPort": 443, "protocol": "TCP"}, "policyNames": []
                          }
                     ]}]

        m = Mock()
        m.query = Mock(side_effect=ret_list)
        eddaclient.updateonly = Mock(return_value=m)
        self.plugin.init(eddaclient, self.config, {})

        # run the tested method
        result = self.plugin.run()
        self.assertEqual(1, len(result))
        self.assertIn('id', result[0])
        self.assertIn('plugin_name', result[0])
        self.assertIn('details', result[0])

        self.assertTrue(isinstance(result[0]['details'], list))
        self.assertEqual(1, len(result[0]['details']))

        m.query.assert_has_calls([call('/api/v2/aws/loadBalancers;_expand')])


def main():
    unittest.main()

if __name__ == '__main__':
    main()
