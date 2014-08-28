#!/usr/bin/env python
import socket
import unittest
from mock import patch, Mock, call

from api import InstanceEnricher
from plugins import MissingInstanceTagPlugin


class PluginMissingInstanceTagTestCase(unittest.TestCase):

    def setUp(self):
        self.plugin = MissingInstanceTagPlugin()
        self.assertEqual(self.plugin.plugin_name, 'missingtag')

    def test_run(self, *mocks):
        instance_enricher = InstanceEnricher(Mock())
        eddaclient = Mock()
        eddaclient._since = 200

        def ret_list(args):
            return [
                {'imageId': 'ami-1', 'instanceId': 'a', 'launchTime': 400, "tags": [{"key": "Name", "value": "tag1"}]},
                {'imageId': 'ami-2', 'instanceId': 'b', 'launchTime': 600,
                    "tags": [{"key": "service_name", "value": "foo"}]},
                {'imageId': 'ami-3', 'instanceId': 'c', 'launchTime': 800, "tags":
                    [{"key": "Name", "value": "tag1"}, {"key": "service_name", "value": "foo"}]},
            ]

        m = Mock()
        m.query = Mock(side_effect=ret_list)
        eddaclient.clean = Mock(return_value=m)
        self.plugin.init(eddaclient, Mock(), {}, instance_enricher)

        # run the tested method
        result = self.plugin.run()

        self.assertEqual(1, len(result))
        result = result[0]
        self.assertEqual("tag1", result["id"]) # service_type became the new id, which in this case is the Name tag
        self.assertEqual(1, len(result["details"]))
        self.assertIn("instanceId", result["details"][0])

        m.query.assert_has_calls([call('/api/v2/view/instances;_expand')])


def main():
    unittest.main()

if __name__ == '__main__':
    main()
