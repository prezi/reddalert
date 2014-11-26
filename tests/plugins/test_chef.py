#!/usr/bin/env python

import unittest
from mock import patch, Mock, call, MagicMock

from api import InstanceEnricher
from plugins import NonChefPlugin


class PluginNonChefTestCase(unittest.TestCase):

    def setUp(self):
        self.plugin = NonChefPlugin()
        self.assertEqual(self.plugin.plugin_name, 'non_chef')
        # self.buckets = ['bucket1', 'bucket2', 'assets', 'bucket3']
        self.config = {'chef_server_url': 'foo',
                       'client_name': 'bar', 'client_key_file': '<key_file>',
                       "excluded_instances": ["jenkins"]}

    def test_initialize(self, *mocks):
        with patch('plugins.chef.ChefAPI') as mock:
            self.plugin.init(Mock(), self.config, {}, Mock())
            self.assertEqual(self.plugin.excluded_instances, ['jenkins'])
            mock.assert_called_once_with('foo', '<key_file>', 'bar')

    @patch('plugins.chef.ChefAPI')
    def test_empty_status(self, *mocks):
        instance_enricher = InstanceEnricher(Mock())
        eddaclient = Mock()

        def ret_list(args):
            return [
                {'keyName': 'keyName1', 'instanceId': 'a', 'privateIpAddress': '10.1.1.1', 'publicIpAddress': '1.1.1.1',
                 "tags": [{"key": "Name", "value": "tag1"}, {'a': 'b'}]},
                {'keyName': 'keyName2', 'instanceId': 'b', 'privateIpAddress': '10.1.1.2', 'publicIpAddress': '2.1.1.1',
                 "tags": [{"key": "service_name", "value": "foo"}]},
                {'keyName': 'keyName3', 'instanceId': 'c', 'privateIpAddress': '10.1.1.3', 'publicIpAddress': '3.1.1.1',
                 'securityGroups': ['foobar']},
                {'keyName': 'keyName4', 'instanceId': 'd', 'privateIpAddress': '10.1.1.4', 'publicIpAddress': '4.1.1.1'}
            ]

        m = Mock()
        m.query = Mock(side_effect=ret_list)
        eddaclient.clean = Mock(return_value=m)
        eddaclient._since = 0

        def chef_list(*args, **kwargs):
            return [{'name': 'host0', 'automatic': {'cloud': {'public_ipv4': '3.1.1.1'}}},
                    {'name': 'host1', 'automatic': {'cloud': {'public_ipv4': '4.1.1.1'}}},
                    {'name': 'host2', 'automatic': {'cloud': {'public_ipv4': '10.1.1.1'}}},
                    {'name': 'host3', 'automatic': {'cloud': {'foo': '2.1.1.1'}}},
                    {'name': 'host4', 'automatic': {'foo': {'public_ipv4': '2.1.1.1'}}},
                    {'foo': {'cloud': {'public_ipv4': '2.1.1.1'}}}]

        with patch('plugins.chef.Search', side_effect=chef_list) as MockClass:
            self.plugin.init(eddaclient, self.config, {}, instance_enricher)

            # run the tested method
            self.assertEqual(list(self.plugin.do_run()), [
                             {'id': 'keyName1-tag1', 'plugin_name': 'non_chef', 'details': [
                              {'tags': {'Name': 'tag1'}, 'instanceId': 'a', 'keyName': 'keyName1', 'securityGroups': [],
                               'publicIpAddress': '1.1.1.1', 'privateIpAddress': '10.1.1.1', 'elbs': [], 'open_ports': [],
                               'service_type': 'tag1', 'started': 0}]},
                             {'id': 'keyName2-foo', 'plugin_name': 'non_chef', 'details': [
                              {'tags': {'service_name': 'foo'}, 'instanceId': 'b', 'keyName': 'keyName2', 'securityGroups': [],
                               'publicIpAddress': '2.1.1.1', 'privateIpAddress': '10.1.1.2', 'elbs': [], 'open_ports': [],
                               'service_type': 'foo', 'started': 0}]}
                             ])

    @patch('plugins.chef.ChefAPI')
    def test_nonempty_status(self, *mocks):
        instance_enricher = InstanceEnricher(Mock())
        eddaclient = Mock()

        def ret_list(args):
            return [
                {'keyName': 'keyName1', 'instanceId': 'a', 'privateIpAddress': '10.1.1.1', 'publicIpAddress': '1.1.1.1',
                 "tags": [{"key": "Name", "value": "tag1"}, {'a': 'b'}], 'launchTime': 12},
                {'keyName': 'keyName2', 'instanceId': 'b', 'privateIpAddress': '10.1.1.2', 'publicIpAddress': '2.1.1.1',
                 "tags": [{"key": "service_name", "value": "foo"}], 'launchTime': 13},
                {'keyName': 'keyName3', 'instanceId': 'c', 'privateIpAddress': '10.1.1.3', 'publicIpAddress': '3.1.1.1',
                 'securityGroups': ['foobar'], 'launchTime': 14},
                {'keyName': 'keyName4', 'instanceId': 'd', 'privateIpAddress': '10.1.1.4', 'publicIpAddress': '4.1.1.1',
                 'launchTime': 14},
                {'instanceId': 'e', 'privateIpAddress': 'x', 'publicIpAddress': 'x', 'launchTime': 5},
                {'instanceId': 'f', 'privateIpAddress': 'x', 'publicIpAddress': 'x', 'launchTime': 13},
            ]

        m = Mock()
        m.query = Mock(side_effect=ret_list)
        eddaclient.clean = Mock(return_value=m)
        eddaclient._since = 10

        def chef_list(*args, **kwargs):
            return [{'name': 'host0', 'automatic': {'cloud': {'public_ipv4': '3.1.1.1'}}},
                    {'name': 'host1', 'automatic': {'cloud': {'public_ipv4': '4.1.1.1'}}},
                    {'name': 'host2', 'automatic': {'cloud': {'public_ipv4': '10.1.1.1'}}},
                    {'name': 'host3', 'automatic': {'cloud': {'foo': '2.1.1.1'}}},
                    {'name': 'host4', 'automatic': {'foo': {'public_ipv4': '2.1.1.1'}}},
                    {'foo': {'cloud': {'public_ipv4': '2.1.1.1'}}}]

        with patch('plugins.chef.Search', side_effect=chef_list) as MockClass:
            self.plugin.init(eddaclient, self.config, {"first_seen": {'f': 8}}, instance_enricher)

            # run the tested method
            self.assertEqual(list(self.plugin.do_run()), [
                             {'id': 'keyName1-tag1', 'plugin_name': 'non_chef', 'details': [
                              {'tags': {'Name': 'tag1'}, 'instanceId': 'a', 'keyName': 'keyName1', 'securityGroups': [],
                               'publicIpAddress': '1.1.1.1', 'privateIpAddress': '10.1.1.1', 'service_type': 'tag1',
                               'elbs': [], 'open_ports': [], 'started': 12}]},
                             {'id': 'keyName2-foo', 'plugin_name': 'non_chef', 'details': [
                              {'tags': {'service_name': 'foo'}, 'instanceId': 'b', 'keyName': 'keyName2', 'securityGroups': [],
                               'publicIpAddress': '2.1.1.1', 'privateIpAddress': '10.1.1.2', 'service_type': 'foo',
                               'elbs': [], 'open_ports': [], 'started': 13}]}
                             ])


def main():
    unittest.main()

if __name__ == '__main__':
    main()
