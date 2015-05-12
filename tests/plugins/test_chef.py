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
    def test_handle_invalid_chef_data(self, *mocks):
        instance_enricher = InstanceEnricher(Mock())
        eddaclient = Mock()

        def ret_list(args):
            return [
                {'keyName': 'keyName1', 'instanceId': 'a', 'privateIpAddress': '10.1.1.1', 'publicIpAddress': '1.1.1.1',
                 "tags": [{"key": "Name", "value": "tag1"}, {'a': 'b'}], 'launchTime': 1 * 3600000},
                {'keyName': 'keyName2', 'instanceId': 'b', 'privateIpAddress': '10.1.1.2', 'publicIpAddress': '2.1.1.1',
                 "tags": [{"key": "service_name", "value": "foo"}], 'launchTime': 1 * 3600000},
                {'keyName': 'keyName3', 'instanceId': 'c', 'privateIpAddress': '10.1.1.3', 'publicIpAddress': '3.1.1.1',
                 'launchTime': 1 * 3600000},
                {'keyName': 'keyName4', 'instanceId': 'd', 'privateIpAddress': '10.1.1.4', 'publicIpAddress': '4.1.1.1',
                 'launchTime': 1 * 3600000}
            ]

        m = Mock()
        m.query = Mock(side_effect=ret_list)
        eddaclient.soft_clean = Mock(return_value=m)
        eddaclient._since = 3 * 3600000
        eddaclient._until = 4 * 3600000 + 1

        def chef_list(*args, **kwargs):
            return [
                {'name': 'host3', 'automatic': {'cloud': {'foo': '1.1.1.1'}}},
                {'name': 'host4', 'automatic': {'foo': {'public_ipv4': '2.1.1.1'}}},
                {'foo': {'cloud': {'public_ipv4': '3.1.1.1'}}}
            ]

        with patch('plugins.chef.Search', side_effect=chef_list):
            self.plugin.init(eddaclient, self.config, {}, instance_enricher)

            alerts = list(self.plugin.do_run())

            # no valid chef data was returned, all the 4 elements are non-chef
            self.assertEqual(4, len(alerts))

    @patch('plugins.chef.ChefAPI')
    def test_empty_status(self, *mocks):
        instance_enricher = InstanceEnricher(Mock())
        eddaclient = Mock()

        def ret_list(args):
            return [
                {'keyName': 'keyName1', 'instanceId': 'a', 'privateIpAddress': '10.1.1.1', 'publicIpAddress': '1.1.1.1',
                 "tags": [{"key": "Name", "value": "tag1"}, {'a': 'b'}], 'launchTime': 1 * 3600000},
                {'keyName': 'keyName2', 'instanceId': 'b', 'privateIpAddress': '10.1.1.2', 'publicIpAddress': '2.1.1.1',
                 "tags": [{"key": "service_name", "value": "foo"}], 'launchTime': 1 * 3600000},
                {'keyName': 'keyName3', 'instanceId': 'c', 'privateIpAddress': '10.1.1.3', 'publicIpAddress': '3.1.1.1',
                 'launchTime': 1 * 3600000},
                {'keyName': 'keyName4', 'instanceId': 'd', 'privateIpAddress': '10.1.1.4', 'publicIpAddress': '4.1.1.1',
                 'launchTime': 1 * 3600000},
                {'keyName': 'keyName5', 'instanceId': 'e', 'privateIpAddress': 'null', 'publicIpAddress': 'null',
                 'launchTime': 1 * 3600000},
                {'keyName': 'keyName6', 'instanceId': 'f', 'privateIpAddress': None, 'publicIpAddress': None,
                 'launchTime': 1 * 3600000}
            ]

        m = Mock()
        m.query = Mock(side_effect=ret_list)
        eddaclient.soft_clean = Mock(return_value=m)
        eddaclient._since = 3 * 3600000
        eddaclient._until = 4 * 3600000 + 1

        def chef_list(*args, **kwargs):
            return [
                {'name': 'host0', 'automatic': {'cloud': {'public_ipv4': '1.1.1.1'}}},
                {'name': 'host1', 'automatic': {'cloud': {'public_ipv4': '2.1.1.1'}}},
                {'name': 'host2', 'automatic': {'cloud': {'public_ipv4': '5.1.1.1'}}},
                ]

        with patch('plugins.chef.Search', side_effect=chef_list) as MockClass:
            self.plugin.init(eddaclient, self.config, {}, instance_enricher)

            alerts = list(self.plugin.do_run())
            # there are two reportable instances, 3.1.1.1 and 4.1.1.1
            self.assertEqual(2, len(alerts))
            self.assertTrue(any(a["details"][0]["publicIpAddress"] == "3.1.1.1" for a in alerts))
            self.assertTrue(any(a["details"][0]["publicIpAddress"] == "4.1.1.1" for a in alerts))

    @patch('plugins.chef.ChefAPI')
    def test_nonempty_status(self, *mocks):
        instance_enricher = InstanceEnricher(Mock())
        eddaclient = Mock()

        def ret_list(args):
            return [
                {'keyName': 'keyName1', 'instanceId': 'a', 'privateIpAddress': '10.1.1.1', 'publicIpAddress': '1.1.1.1',
                 "tags": [{"key": "Name", "value": "tag1"}, {'a': 'b'}], 'launchTime': 6 * 3600000 + 1},
                {'keyName': 'keyName2', 'instanceId': 'b', 'privateIpAddress': '10.1.1.2', 'publicIpAddress': '2.1.1.1',
                 "tags": [{"key": "service_name", "value": "foo"}], 'launchTime': 7 * 3600000 + 1},
                {'keyName': 'keyName3', 'instanceId': 'c', 'privateIpAddress': '10.1.1.3', 'publicIpAddress': '3.1.1.1',
                 'launchTime': 8 * 3600000 + 1},
                {'keyName': 'keyName4', 'instanceId': 'd', 'privateIpAddress': '10.1.1.4', 'publicIpAddress': '4.1.1.1',
                 'launchTime': 9 * 3600000 + 1},
                {'instanceId': 'e', 'privateIpAddress': 'x', 'publicIpAddress': 'x', 'launchTime': 10 * 3600000 + 1},
                {'instanceId': 'f', 'privateIpAddress': 'x', 'publicIpAddress': 'x', 'launchTime': 11 * 3600000 + 1},
            ]

        m = Mock()
        m.query = Mock(side_effect=ret_list)
        eddaclient.soft_clean = Mock(return_value=m)
        eddaclient._since = 10 * 3600000
        eddaclient._until = 11 * 3600000

        def chef_list(*args, **kwargs):
            return [
                {'name': 'host0', 'automatic': {'cloud': {'public_ipv4': '5.1.1.1'}}},
                {'name': 'host1', 'automatic': {'cloud': {'public_ipv4': '6.1.1.1'}}},
                {'name': 'host2', 'automatic': {'cloud': {'public_ipv4': '7.1.1.1'}}},
            ]

        with patch('plugins.chef.Search', side_effect=chef_list) as MockClass:
            self.plugin.init(eddaclient, self.config, {"first_seen": {'f': 8}}, instance_enricher)

            alerts = list(self.plugin.do_run())
            # there is one problematic node (2.1.1.1)
            self.assertEqual(1, len(alerts))
            self.assertTrue(any(a["details"][0]["publicIpAddress"] == "2.1.1.1" for a in alerts))


def main():
    unittest.main()

if __name__ == '__main__':
    main()
