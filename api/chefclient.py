import json
import urllib
import time

import logging
from IPy import IP
from chef import ChefAPI

from chef.exceptions import ChefServerError


class ChefClient:
    def __init__(self, chef_api, plugin_name):
        """

        :type chef_api: ChefAPI
        """
        self.chef_api = chef_api
        self.logger = logging.getLogger(plugin_name)

    def search_chef_hosts(self, requested_node_attributes, query='*:*', chunk_size=2000):
        results = []
        for offset in xrange(5):
            get_params = urllib.urlencode({'q': query, 'start': offset * chunk_size, 'rows': chunk_size})
            for retry in xrange(5):
                try:
                    search_result = self.chef_api.request('POST', '/search/node?{}'.format(get_params),
                                                          headers={'accept': 'application/json'},
                                                          data=json.dumps(requested_node_attributes)
                                                          )
                    result_list = json.loads(search_result).get('rows', [])
                    node_list = [node.get('data', {}) for node in result_list]
                    results.extend(node_list)
                    break
                except ChefServerError:
                    if retry == 4:
                        self.logger.exception("Chef API failed after 5 retries: POST /search/node")
                    time.sleep(5)
        return results
