#!/usr/bin/env python
import socket
import unittest

from mock import patch, Mock, call
from plugins import SecurityGroupPlugin


class PluginSecurityGroupTestCase(unittest.TestCase):
    def setUp(self):
        self.plugin = SecurityGroupPlugin()
        self.assertEqual(self.plugin.plugin_name, 'secgroups')
        self.config = {'allowed_ports': [22], 'whitelisted_ips': ['1.2.3.4/24', '2.2.2.2/32']}

    def test_is_suspicious(self):
        self.plugin.init(Mock(), self.config, {})

        self.assertTrue(self.plugin.is_suspicious(
            {"fromPort": None, "ipProtocol": "-1", "ipRanges": ["0.0.0.0/0"], "toPort": None}))
        self.assertTrue(self.plugin.is_suspicious(
            {"fromPort": 25, "ipProtocol": "tcp", "ipRanges": ["0.0.0.0/0"], "toPort": 25}))
        self.assertTrue(self.plugin.is_suspicious(
            {"fromPort": 21, "ipProtocol": "tcp", "ipRanges": ["6.6.6.6/32"], "toPort": 22}))
        self.assertTrue(self.plugin.is_suspicious(
            {"fromPort": 80, "ipProtocol": "tcp", "ipRanges": ["6.6.6.6/32"], "toPort": 80}))

        self.assertFalse(self.plugin.is_suspicious(
            {"fromPort": 0, "ipProtocol": "icmp", "ipRanges": ["0.0.0.0/0"], "toPort": -1}))
        self.assertFalse(self.plugin.is_suspicious(
            {"fromPort": 8, "ipProtocol": "icmp", "ipRanges": ["0.0.0.0/0"], "toPort": -1}))
        self.assertFalse(self.plugin.is_suspicious(
            {"fromPort": 22, "ipProtocol": "tcp", "ipRanges": ["0.0.0.0/0"], "toPort": 22}, ))
        self.assertFalse(self.plugin.is_suspicious(
            {"fromPort": 25, "ipProtocol": "icmp", "ipRanges": ["0.0.0.0/0"], "toPort": 26}, ))
        self.assertFalse(self.plugin.is_suspicious(
            {"fromPort": 80, "ipProtocol": "tcp", "ipRanges": ["2.2.2.2/32"], "toPort": 80}))
        self.assertFalse(self.plugin.is_suspicious(
            {"fromPort": None, "ipProtocol": "-1", "ipRanges": ["1.2.3.4/24", "2.2.2.2/32"], "toPort": None}))

    def test_is_port_open(self, *mocks):
        self.plugin.init(Mock(), self.config, {})

        with patch('socket.socket') as MockClass:
            instance = MockClass.return_value
            # too big range
            self.assertEqual(self.plugin.is_port_open('127.0.0.1', 1, 443), None)

            # bad arguments
            self.assertFalse(self.plugin.is_port_open(None, 22, 22))
            self.assertFalse(self.plugin.is_port_open(22, None, 22))
            self.assertFalse(self.plugin.is_port_open(22, 22, None))
            self.assertFalse(self.plugin.is_port_open('22', -1, 22))
            self.assertFalse(self.plugin.is_port_open('22', 22, -1))
            self.assertFalse(self.plugin.is_port_open('22', 65536, 22))
            self.assertFalse(self.plugin.is_port_open('22', 22, 65536))

            # should be ok
            self.assertTrue(self.plugin.is_port_open('127.0.0.1', 22, 22))

            # socket error/timeout
            instance.connect.side_effect = socket.timeout
            self.assertFalse(self.plugin.is_port_open('127.0.0.1', 22, 22))
            instance.connect.side_effect = socket.error
            self.assertFalse(self.plugin.is_port_open('127.0.0.1', 22, 22))

    @patch('plugins.SecurityGroupPlugin.is_port_open', return_value=True)
    def test_run(self, *mocks):
        eddaclient = Mock()

        def ret_list(args):
            return [{"groupId": "sg-1", "groupName": "group1", "ipPermissions": [
                {"fromPort": 22, "ipProtocol": "tcp", "ipRanges": ["0.0.0.0/0"], "toPort": 22},
                {"fromPort": 0, "ipProtocol": "icmp", "ipRanges": ["0.0.0.0/0"], "toPort": -1}]},
                    {"groupId": "sg-2", "groupName": "group2", "ipPermissions": [
                        {"fromPort": 139, "ipProtocol": "tcp", "ipRanges": ["0.0.0.0/0"], "toPort": 139}]},
                    {"groupId": "sg-3", "groupName": "empty group"}
                    ]

        def ret_machines(args):
            return [
                {'imageId': 'ami-1', 'instanceId': 'a', 'publicIpAddress': '1.1.1.1', "tags": [], "securityGroups":
                    [{"groupId": "sg-1", "groupName": "group1"}]},
                {'imageId': 'ami-1', 'instanceId': 'b', 'publicIpAddress': '2.1.1.1', "tags": [
                    {"key": "Name", "value": "tag1"}], 'securityGroups': [
                    {"groupId": "sg-2", "groupName": "group2"},
                    {"groupId": "sg-1", "groupName": "group1"}]},
                {'imageId': 'ami-2', 'instanceId': 'c', 'publicIpAddress':
                    '3.1.1.1', "tags": [], 'securityGroups': []},
                {'imageId': 'ami-3', 'instanceId': 'd', 'publicIpAddress': '4.1.1.1', "tags": [], 'securityGroups':
                    [{"groupId": "sg-4", "groupName": "group4"}]}
            ]

        m1 = Mock()
        m1.query = Mock(side_effect=ret_list)
        eddaclient.updateonly = Mock(return_value=m1)

        eddaclient.query = Mock(side_effect=ret_machines)
        self.plugin.init(eddaclient, self.config, {})

        # run the tested method
        self.assertEqual(self.plugin.run(), [{'id': 'sg-2 (group2)', 'plugin_name': 'secgroups', 'details': [
            {'fromPort': 139, 'ipRanges': ['0.0.0.0/0'], 'toPort': 139, 'ipProtocol': 'tcp', 'port_open': True,
             'machines': ['b (2.1.1.1): tag1']}]}])

        m1.query.assert_has_calls([call('/api/v2/aws/securityGroups;_expand')])
        eddaclient.query.assert_has_calls([call('/api/v2/view/instances;_expand')])


def main():
    unittest.main()


if __name__ == '__main__':
    main()
