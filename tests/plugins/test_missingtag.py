#!/usr/bin/env python
import socket
import unittest
from mock import patch, Mock, call

from plugins import MissingInstanceTagPlugin


class PluginMissingInstanceTagTestCase(unittest.TestCase):

    def setUp(self):
        self.plugin = MissingInstanceTagPlugin()
        self.assertEqual(self.plugin.plugin_name, 'missingtag')

    def test_run(self, *mocks):

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
        self.plugin.init(eddaclient, Mock(), {})

        # run the tested method
        self.assertEqual(self.plugin.run(), [{'details': ['n/a'], 'id': 'a', 'plugin_name': 'missingtag'}])

        m.query.assert_has_calls([call('/api/v2/view/instances;_expand')])


def main():
    unittest.main()

if __name__ == '__main__':
    main()
