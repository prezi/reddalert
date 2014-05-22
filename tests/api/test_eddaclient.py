#!/usr/bin/env python
import json
import unittest
from mock import patch, Mock
from httpretty import HTTPretty, httprettified
from urllib2 import HTTPError

from api.eddaclient import EddaClient, EddaException


class EddaClientTestCase(unittest.TestCase):

    def setUp(self):
        self.eddaURL = 'http://localhost:8888/edda'
        self.eddaclient = EddaClient(self.eddaURL)
        self.expected_response = ["i-111", "i-222"]

    def test_clone(self):
        self.assertEqual(self.eddaclient.clone().__dict__, self.eddaclient.__dict__)

    def test_clone_modify(self):
        self.assertEqual(self.eddaclient._since, None)
        self.assertEqual(self.eddaclient.clone_modify({'_since': 1})._since, 1)

    @patch('api.eddaclient.EddaClient.do_query', return_value=["i-111", "i-222"])
    def test_query(self, *mocks):
        res = self.eddaclient.query('/api/v2/view/instances')
        self.assertEqual(res, self.expected_response)
        self.assertEqual(self.eddaclient._cache[self.eddaURL + '/api/v2/view/instances'], self.expected_response)

    @httprettified
    def test_do_query(self):
        HTTPretty.register_uri(HTTPretty.GET, self.eddaURL + '/api/v2/view/instances',
                               body=json.dumps(self.expected_response),
                               status=200)
        self.assertEqual(self.eddaclient.query('/api/v2/view/instances'), self.expected_response)

    @httprettified
    def test_do_query_exception(self):
        HTTPretty.register_uri(HTTPretty.GET, self.eddaURL + '/api/v2/view/instances',
                               body='error',
                               status=500)
        self.assertRaises(HTTPError, self.eddaclient.query, ('/api/v2/view/instances'))

    @httprettified
    def test_do_query_error(self):
        HTTPretty.register_uri(HTTPretty.GET, self.eddaURL + '/api/v2/view/instances',
                               body='{"code": "xxxx", "asd": "b"}',
                               status=200)
        self.assertRaises(EddaException, self.eddaclient.query, ('/api/v2/view/instances'))

    @httprettified
    def test_do_query_invalid_json(self):
        HTTPretty.register_uri(HTTPretty.GET, self.eddaURL + '/api/v2/view/instances',
                               body='invalid',
                               status=200)
        self.assertRaises(ValueError, self.eddaclient.query, ('/api/v2/view/instances'))

    @httprettified
    def test_raw_query(self):
        HTTPretty.register_uri(HTTPretty.GET, self.eddaURL + '/api/v2/view/instances',
                               body='raw_response',
                               status=200)
        self.assertEqual(self.eddaclient.raw_query('/api/v2/view/instances'), 'raw_response')


def main():
    unittest.main()

if __name__ == '__main__':
    main()
