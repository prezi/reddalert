#!/usr/bin/env python
import logging
import json
import urllib2


class EddaException(Exception):

    def __init__(self, ret):
        Exception.__init__(self, 'EDDA returned with an error: ' + repr(ret))
        self.response = ret


class BetterHTTPErrorProcessor(urllib2.BaseHandler):
    # a substitute/supplement to urllib2.HTTPErrorProcessor
    # that doesn't raise exceptions on status codes 400

    def http_error_400(self, request, response, code, msg, hdrs):
        return response

opener = urllib2.build_opener(BetterHTTPErrorProcessor)
urllib2.install_opener(opener)


class EddaClient:

    def __init__(self, edda_url):
        self.logger = logging.getLogger("EddaClient")
        self._edda_url = edda_url
        self._every = False
        self._since = None
        self._until = None
        self._updateonly = False
        self._cache = {}

    def clone(self):
        edda_client = EddaClient(self._edda_url)
        edda_client._every = self._every
        edda_client._since = self._since
        edda_client._until = self._until
        edda_client._updateonly = self._updateonly
        edda_client._cache = self._cache
        return edda_client

    def clone_modify(self, uv):
        edda_client = self.clone()
        for key, value in uv.iteritems():
            edda_client.__dict__[key] = value
        return edda_client

    def query(self, uri):
        url = self._construct_uri(uri)
        if url in self._cache:
            return self._cache[url]
        else:
            response = self.do_query(url)
            self._cache[url] = response
            return response

    def do_query(self, url):
        self.logger.info("do_query: '%s'", url)
        try:
            response = urllib2.urlopen(url).read()
            ret = json.loads(response)
            if 'code' in ret:
                # indicates an error in EDDA response
                raise EddaException('EDDA returned with an error: ' + repr(ret))
        except ValueError as e:
            raise ValueError('%s, response: %s' % (e, response))

        return ret

    def raw_query(self, uri):
        url = self._construct_uri(uri)
        self.logger.info("raw_query: '%s'", url)
        try:
            file = urllib2.urlopen(url)
            ret = file.read()
            if file.getcode() != 200:
                print 'EDDAClient got non-200 error code.'
                try:
                    # indicates an error in EDDA response
                    raise EddaException(json.loads(ret))
                except ValueError as e:
                    raise ValueError('Failed to parse EDDA error message: %s, response: %s' % (e, ret))
            return ret
        except urllib2.HTTPError as e:
            print 'Got HTTPError', e
            return ''

    def _construct_uri(self, uri):
        base = self._edda_url + uri
        if self._every:
            base += ';_all'
        if self._since is not None:
            base += ';_since=%s' % self._since
        if self._until is not None:
            base += ';_until=%s' % self._until
        if self._updateonly:
            base += ';_updated'

        return base

    def every(self):
        return self.clone_modify({'_every': True})

    def updateonly(self):
        return self.clone_modify({'_updateonly': True})

    def since(self, since):
        return self.clone_modify({'_since': since})

    def until(self, until):
        return self.clone_modify({'_until': until})

    def with_cache(self, cache):
        return self.clone_modify({'_cache': cache})

    def clean(self):
        return EddaClient(self._edda_url)

    def soft_clean(self):
        return self.clean().with_cache(self._cache)
