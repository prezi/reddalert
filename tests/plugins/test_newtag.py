#!/usr/bin/env python
import unittest
from mock import patch, Mock, call

from plugins import NewInstanceTagPlugin
from api import InstanceEnricher


class PluginNewInstanceTagTestCase(unittest.TestCase):

    def setUp(self):
        self.plugin = NewInstanceTagPlugin()
        self.assertEqual(self.plugin.plugin_name, 'newtag')

    def test_run(self, *mocks):
        instance_enricher = InstanceEnricher(Mock())
        eddaclient = Mock()
        eddaclient._since = 500

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
        self.assertEqual("foo", result["id"])
        self.assertEqual(2, len(result["details"]))
        self.assertIn("b", [d["instanceId"] for d in result["details"]])
        self.assertIn("c", [d["instanceId"] for d in result["details"]])

        m.query.assert_has_calls([call('/api/v2/view/instances;_expand')])


def main():
    unittest.main()

if __name__ == '__main__':
    main()
