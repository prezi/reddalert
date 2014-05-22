#!/usr/bin/env python
import os
import unittest
from mock import Mock, call

from plugins import UserAddedPlugin

APPDIR = "%s/" % os.path.dirname(os.path.realpath(__file__ + '/../'))


class PluginIamTestCase(unittest.TestCase):

    def setUp(self):
        self.plugin = UserAddedPlugin()
        self.assertEqual(self.plugin.plugin_name, 'iam')

    def test_run(self, *mocks):

        eddaclient = Mock()
        default_users = ['bob', 'alice']
        whitelisted_users = ['whitelisteduser123123']
        allowed_list = ['^whitelisteduser[\d]{6}$']
        users = default_users + whitelisted_users
        diff_call_format = '/api/v2/aws/iamUsers/%s;_diff=200'

        def ret_list(args):
            return users

        def ret_user_diff(args):
            if args == diff_call_format % 'alice':
                return open(APPDIR + 'test_data/test_iam_diff.txt').read()
            else:
                return '"diff" without group change'

        m = Mock()
        m.query = Mock(side_effect=ret_list)
        eddaclient.raw_query = Mock(side_effect=ret_user_diff)
        eddaclient.updateonly = Mock(return_value=m)

        mocked_config = {}
        mocked_config['allowed'] = allowed_list

        self.plugin.init(eddaclient, mocked_config, {})

        # run the tested method
        self.assertEqual(self.plugin.run(), [
            {'id': 'alice', 'plugin_name': 'iam',
             'details': ['Groups the user has been added to: developers, devops']}])

        m.query.assert_has_calls([call('/api/v2/aws/iamUsers')])
        # switched to assertEqual so we can detect if the whitelisted user is indeed not checked
        self.assertEqual(eddaclient.raw_query.call_args_list, [call(diff_call_format % username) for username in default_users])


def main():
    unittest.main()

if __name__ == '__main__':
    main()
