#!/usr/bin/env python
import os
import unittest
from mock import patch, Mock, call

from plugins import NewAMIPlugin
from api import InstanceEnricher


class PluginAmiTestCase(unittest.TestCase):

    def setUp(self):
        self.plugin = NewAMIPlugin()
        self.assertEqual(self.plugin.plugin_name, 'ami')
        self.config = {"allowed_tags": ['jenkins']}

    def test_initialize(self):
        self.plugin.init(Mock(), self.config, {}, Mock())
        self.assertEqual(self.plugin.status, {'first_seen': {}})
        expected = {'first_seen': {"ami-111": 1392015440000}, 'a': 3}
        self.plugin.init(Mock(), self.config, expected, Mock())
        self.assertEqual(self.plugin.status, expected)

    def test_run(self, *mocks):
        instance_enricher = InstanceEnricher(Mock())

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
        eddaclient.soft_clean = Mock(return_value=m)
        self.plugin.init(eddaclient, self.config, {'first_seen': {"ami-1": 1000, "ami-2": 400}}, instance_enricher)

        result = self.plugin.run()

        self.assertEqual(1, len(result))
        result = result[0]
        self.assertEqual('ami-1', result['id'])
        self.assertEqual(2, len(result['details']))
        self.assertIn('a', [d['instanceId'] for d in result['details']])
        self.assertIn('b', [d['instanceId'] for d in result['details']])

        m.query.assert_has_calls([call('/api/v2/view/instances;_expand')])
        self.assertEqual(self.plugin.status, {'first_seen': {'ami-1': 500, 'ami-2': 400}})

    def test_skipped_service(self):
        instance_enricher = InstanceEnricher(Mock())
        eddaclient = Mock()
        eddaclient.query = Mock(return_value=[
            {'imageId': 'ami-1', 'instanceId': 'b', 'launchTime': '2000',
             'tags': [{'key': 'service_name', 'value': 'jenkins'}]}])
        uncleaned_eddaclient = Mock()
        uncleaned_eddaclient.soft_clean = Mock(return_value=eddaclient)
        uncleaned_eddaclient._since = 500

        self.plugin.init(uncleaned_eddaclient, self.config, {'first_seen': {}}, instance_enricher)

        real = self.plugin.run()
        expected = []

        self.assertEqual(expected, real)
        eddaclient.query.assert_has_calls([call('/api/v2/view/instances;_expand')])


def main():
    unittest.main()

if __name__ == '__main__':
    main()
