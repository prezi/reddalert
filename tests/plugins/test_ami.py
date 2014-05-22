#!/usr/bin/env python
import os
import unittest
from mock import patch, Mock, call

from plugins import NewAMIPlugin


class PluginAmiTestCase(unittest.TestCase):

    def setUp(self):
        self.plugin = NewAMIPlugin()
        self.assertEqual(self.plugin.plugin_name, 'ami')
        self.config = {"allowed_tags": ['jenkins']}

    def test_initialize(self):
        self.plugin.init(Mock(), self.config, {})
        self.assertEqual(self.plugin.status, {'first_seen': {}})
        expected = {'first_seen': {"ami-111": 1392015440000}, 'a': 3}
        self.plugin.init(Mock(), self.config, expected)
        self.assertEqual(self.plugin.status, expected)

    def test_run(self, *mocks):

        eddaclient = Mock()
        eddaclient._since = 500

        def ret_list(args):
            return [
                {'imageId': 'ami-1', 'instanceId': 'a', 'launchTime': '500',
                 'tags': [{'key': 'service_name', 'value': 'conversion'}, {'key': 'started_by', 'value': 'john'}]},
                {'imageId': 'ami-1', 'instanceId': 'b', 'launchTime': '2000',
                 'tags': [{'key': 'service_name', 'value': 'router'}]},
                {'imageId': 'ami-2', 'instanceId': 'c', 'launchTime': '400'}]

        m = Mock()
        m.query = Mock(side_effect=ret_list)
        eddaclient.clean = Mock(return_value=m)
        self.plugin.init(eddaclient, self.config, {'first_seen': {"ami-1": 1000, "ami-2": 400}})

        real = self.plugin.run()
        expected = [
            {'id': 'ami-1', 'plugin_name': 'ami', 'details': [
                ('a', 500, [{'service_name': 'conversion'}, {'started_by': 'john'}]),
                ('b', 2000, [{'service_name': 'router'}])]}
        ]

        self.assertEqual(expected, real)

        m.query.assert_has_calls([call('/api/v2/view/instances;_expand')])
        self.assertEqual(self.plugin.status, {'first_seen': {'ami-1': 500, 'ami-2': 400}})

    def test_skipped_service(self):
        eddaclient = Mock()
        eddaclient.query = Mock(return_value=[
            {'imageId': 'ami-1', 'instanceId': 'b', 'launchTime': '2000',
             'tags': [{'key': 'service_name', 'value': 'jenkins'}]}])
        uncleaned_eddaclient = Mock()
        uncleaned_eddaclient.clean = Mock(return_value=eddaclient)
        uncleaned_eddaclient._since = 500

        self.plugin.init(uncleaned_eddaclient, self.config, {'first_seen': {}})

        real = self.plugin.run()
        expected = []

        self.assertEqual(expected, real)
        eddaclient.query.assert_has_calls([call('/api/v2/view/instances;_expand')])


def main():
    unittest.main()

if __name__ == '__main__':
    main()
