#!/usr/bin/env python
import unittest
import os
from mock import patch, Mock, call
from reddalert import Reddalert

APPDIR = "%s/" % os.path.dirname(os.path.realpath(__file__))


class ReddalertTestCase(unittest.TestCase):

    def setUp(self):
        self.reddalert = Reddalert
        self.test_status_file = APPDIR + 'test_data/test_status_file.json'
        self.test_invalid_json = APPDIR + 'test_data/test_invalid.json'
        self.test_json_data = {
            u'plugin.newtag': {},
            u'plugin.iam': {},
            u'since': 1392126281000,
            u'plugin.elbs': {}, u'plugin.missingtag': {},
            u'plugin.s3acl': {},
            u'plugin.secgroups': {},
            u'plugin.ami': {u'first_seen': {u'ami-111': 1392100947000}}
        }

    def test_get_since(self):
        self.assertEqual(self.reddalert.get_since('2014-02-10 00:00:00'), 1391990400000)
        self.assertEqual(self.reddalert.get_since('123456789'), 123456789)
        self.assertEqual(self.reddalert.get_since('asd'), None)
        self.assertEqual(self.reddalert.get_since(''), None)
        self.assertEqual(self.reddalert.get_since(12345678), None)

    def test_load_json(self):
        logger = Mock()

        self.assertEqual(self.reddalert.load_json('asd', logger), {})
        self.assertEqual(self.reddalert.load_json(self.test_status_file, logger), self.test_json_data)

        self.assertEqual(self.reddalert.load_json(self.test_invalid_json, logger), {})
        self.assertEqual(logger.mock_calls, [
            call.exception("Failed to read file '%s'", 'asd'),
            call.exception("Invalid JSON file '%s'", self.test_invalid_json)
        ])

    def test_save_json(self):
        logger = Mock()

        self.assertFalse(self.reddalert.save_json('/tmp', {}, logger))
        self.assertFalse(self.reddalert.save_json('/tmp' * 100, {'foo': 'bar'}, logger))
        self.assertTrue(self.reddalert.save_json('/tmp/reddalert_test.tmp', self.test_json_data, logger))

        self.assertEqual(logger.mock_calls, [
            call.warning('Got empty JSON content, not updating status file!'),
            call.exception("Failed to write file '%s'", '/tmp' * 100)
        ])

    def test_get_config(self):
        config = {'b': 1}
        self.assertEqual(self.reddalert.get_config('b', config), 1)
        self.assertEqual(self.reddalert.get_config('a', config), None)
        self.assertEqual(self.reddalert.get_config('a', config, 'arg'), 'arg')
        self.assertEqual(self.reddalert.get_config('b', config, 'arg'), 'arg')
        self.assertEqual(self.reddalert.get_config('b', config, None, 'default'), 1)
        self.assertEqual(self.reddalert.get_config('a', config, None, 'default'), 'default')


def main():
    unittest.main()

if __name__ == '__main__':
    main()
