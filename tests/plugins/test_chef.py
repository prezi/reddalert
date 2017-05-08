#!/usr/bin/env python
import json
import unittest

from mock import patch, Mock, MagicMock

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

    def wrap_chef_result(self, node):
        if node:
            return json.dumps({'rows': [{'data': node}]})
        else:
            return json.dumps({'rows': []})

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

        chef_result_list = [
            self.wrap_chef_result({'name': 'host3', 'cloud_foo': '1.1.1.1'}),
            self.wrap_chef_result({'name': 'host4'}),
            self.wrap_chef_result({'foo_what': 'bar', 'cloud_public_ipv6': ':da7a::', 'cloud_provider': 'ec2'}),
            self.wrap_chef_result(None),
            self.wrap_chef_result(None)
        ]

        with patch('plugins.chef.ChefAPI', return_value=MagicMock(request=MagicMock(side_effect=chef_result_list))):
            self.plugin.init(eddaclient, self.config, {}, instance_enricher)

            alerts = list(self.plugin.do_run())
            # no valid chef data was returned
            self.assertEqual(0, len(alerts))

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

        chef_result_list = [
            self.wrap_chef_result({'name': 'ec2 alive', 'cloud_public_ipv4': '1.1.1.1', 'cloud_provider': 'ec2'}),
            self.wrap_chef_result({'name': 'non-ec2 but cloud host alive', 'cloud_public_ipv4': '2.1.1.1'}),
            self.wrap_chef_result({'name': 'ec2 host dead', 'cloud_public_ipv4': '255.1.1.1', 'cloud_provider': 'ec2'}),
            self.wrap_chef_result({'name': 'non-ec2 host', 'ipaddress': '5.1.1.1'}),
            self.wrap_chef_result(None)
        ]

        with patch('plugins.chef.ChefAPI', return_value=MagicMock(request=MagicMock(side_effect=chef_result_list))):
            self.plugin.init(eddaclient, self.config, {}, instance_enricher)
            alerts = list(self.plugin.do_run())
            non_chef_alerts = [i for i in alerts if i['plugin_name'] == 'non_chef']
            chef_managed_alerts = [i for i in alerts if i['plugin_name'] == 'chef_managed']

            # there are two reportable instances, 3.1.1.1 and 4.1.1.1
            self.assertEqual(2, len(non_chef_alerts))
            self.assertTrue(any(a["details"][0]["publicIpAddress"] == "3.1.1.1" for a in non_chef_alerts))
            self.assertTrue(any(a["details"][0]["publicIpAddress"] == "4.1.1.1" for a in non_chef_alerts))

            self.assertEqual(3, len(chef_managed_alerts))
            self.assertTrue(any(a["details"][0]["publicIpAddress"] == "1.1.1.1" for a in chef_managed_alerts))
            self.assertTrue(any(a["details"][0]["publicIpAddress"] == "2.1.1.1" for a in chef_managed_alerts))
            self.assertTrue(any(a["details"][0]["publicIpAddress"] == "5.1.1.1" for a in chef_managed_alerts))

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
                {'instanceId': 'f', 'privateIpAddress': 'x', 'publicIpAddress': '7.1.1.1', 'launchTime': 11 * 3600000 + 1},
            ]

        m = Mock()
        m.query = Mock(side_effect=ret_list)
        eddaclient.soft_clean = Mock(return_value=m)
        eddaclient._since = 10 * 3600000
        eddaclient._until = 11 * 3600000

        chef_result_list = [
            self.wrap_chef_result({'name': 'host0', 'cloud_public_ipv4': '4.1.1.1'}),
            self.wrap_chef_result({'name': 'host1', 'cloud_public_ipv4': '6.1.1.1'}),
            self.wrap_chef_result(None),
            self.wrap_chef_result(None),
            self.wrap_chef_result(None)
        ]

        with patch('plugins.chef.ChefAPI', return_value=MagicMock(request=MagicMock(side_effect=chef_result_list))):
            self.plugin.init(eddaclient, self.config, {"first_seen": {'f': 8}}, instance_enricher)

            alerts = list(self.plugin.do_run())
            non_chef_alerts = [i for i in alerts if i['plugin_name'] == 'non_chef']
            chef_managed_alerts = [i for i in alerts if i['plugin_name'] == 'chef_managed']

            # there is one problematic node (2.1.1.1)
            self.assertEqual(1, len(non_chef_alerts))
            self.assertTrue(any(a["details"][0]["publicIpAddress"] == "2.1.1.1" for a in non_chef_alerts))

            # there is one chef managed node (4.1.1.1)
            self.assertEqual(2, len(chef_managed_alerts))
            self.assertTrue(any(a["details"][0]["publicIpAddress"] == "4.1.1.1" for a in chef_managed_alerts))
            self.assertTrue(any(a["details"][0]["publicIpAddress"] == "6.1.1.1" for a in chef_managed_alerts))


def main():
    unittest.main()


if __name__ == '__main__':
    main()
