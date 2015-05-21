import logging
import urllib
from multiprocessing import Pool

import re
import requests
from .route53 import load_route53_entries, is_external


def fetch_url(location):
    try:
        resp = requests.get(location, allow_redirects=False, timeout=3)
        return location, {'code': resp.status_code, 'headers': resp.headers}
    except:
        pass

    return location, None


class BaseClass:
    def __init__(self):
        pass

    def run(self):
        raise NotImplementedError()

    def load_aws_ips(self):
        aws_machines = self.edda_client.soft_clean().query("/api/v2/view/instances;_expand")
        return [m.get("publicIpAddress") for m in aws_machines]

    def load_known_dns(self):
        route53_zone = self.config.get("zone")
        entries = load_route53_entries(self.edda_client, route53_zone)
        name_map = {e.get("name"): e for e in entries}
        return name_map

    def get_all_my_domains(self):
        ips = self.load_aws_ips()
        legit_domains = self.config.get("legit_domains", [])
        exempts = self.config.get("exception_domains", [])
        dns_names = self.load_known_dns()
        return [name for name, entry in dns_names.iteritems()
                if is_external(entry, ips, legit_domains) and name not in exempts]

    def get_all_my_domains_response(self):
        all_my_domains = self.get_all_my_domains()
        locations_http = ["http://%s" % name for name in all_my_domains]
        locations_https = ["https://%s" % name for name in all_my_domains]
        locations = list(locations_http + locations_https)

        self.logger.info("fetching %d urls on 16 threads" % len(locations))

        return {url: resp for url, resp in Pool(16).map(fetch_url, locations) if resp}


class SSOUnprotected(BaseClass):
    UNPROTECTED = 'unprotected'
    SSO_URL = ''
    GODAUTH_URL = ''

    def __init__(self):
        self.plugin_name = 'sso_unprotected'
        self.logger = logging.getLogger(self.plugin_name)

    def init(self, edda_client, config, status):
        self.edda_client = edda_client
        self.config = config
        self.status = status
        self._initialize_status()

    def _initialize_status(self):
        SSOUnprotected.GODAUTH_URL = self.config['godauth_url']
        SSOUnprotected.SSO_URL = self.config['sso_url']
        if 'redirects' not in self.status:
            self.status['redirects'] = []

    def run(self):
        responses = self.get_all_my_domains_response()
        redirects = {url: urllib.unquote(response['headers'].get('location'))
                     for url, response in responses.iteritems()}

        old_redirects = self.status.get("redirects", {})
        alerts = {
            loc: redirect_url for loc, redirect_url in redirects.iteritems()
            if loc not in old_redirects or old_redirects[loc] != redirect_url
        }
        self.status["redirects"] = redirects
        for location, redirect_url in alerts.iteritems():

            loc_re = re.search('(https?)://(.*)', location)
            red_re = re.search('(https?)://(.*)', redirect_url)
            if self.SSO_URL + location == redirect_url or self.GODAUTH_URL + location == redirect_url:
                continue

            if red_re and loc_re.group(2) == red_re.group(2) and red_re.group(1) == 'https' and loc_re.group(
                    1) == 'http':
                continue

            yield {
                "plugin_name": self.plugin_name,
                "id": location,
                "details": list(["This domain (%s) is neither behind SSO nor GODAUTH because redirects to %s" % (
                    location, redirect_url)])
            }


class SecurityHeaders(BaseClass):
    def __init__(self):
        self.plugin_name = 'security_headers'
        self.logger = logging.getLogger(self.plugin_name)

    def init(self, edda_client, config, status):
        self.edda_client = edda_client
        self.config = config
        self.status = status

    def run(self):
        for location, response in self.get_all_my_domains_response().iteritems():
            if not response['headers'].get('x-frame-options') and 200 <= response['code'] < 300:
                yield {
                    "plugin_name": self.plugin_name,
                    "id": location,
                    "details": list(["This webpage (%s) does not have X-Frame-Options header" % location])
                }
