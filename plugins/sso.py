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


def one_starts_with_another(one, two):
    return one.startswith(two) or two.startswith(one)


class BaseClass:
    PROCESSING_POOL_SIZE = 8

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
        return [name.rstrip('.') for name, entry in dns_names.iteritems()
                if is_external(entry, ips, legit_domains) and name not in exempts]

    def get_all_my_domains_response(self):
        all_my_domains = self.get_all_my_domains()
        locations_http = ["http://%s" % name for name in all_my_domains]
        locations_https = ["https://%s" % name for name in all_my_domains]
        locations = list(locations_http + locations_https)

        self.logger.info("fetching %d urls on %d threads" % (len(locations), self.PROCESSING_POOL_SIZE))

        processing_pool = Pool(self.PROCESSING_POOL_SIZE)
        result = {url: resp for url, resp in processing_pool.map(fetch_url, locations) if resp}
        processing_pool.close()
        return result


class SSOUnprotected(BaseClass):
    UNPROTECTED = 'unprotected'
    SSO_URL = None
    GODAUTH_URL = None
    VALID_URL_RE = re.compile(r'https?://(.*)/?', re.IGNORECASE)

    def __init__(self):
        self.plugin_name = 'sso_unprotected'
        self.logger = logging.getLogger(self.plugin_name)

    def init(self, edda_client, config, status):
        self.edda_client = edda_client
        self.config = config
        self.status = status
        self._initialize_status()

    def _initialize_status(self):
        self.GODAUTH_URL = re.compile(self.config['godauth_url'], re.IGNORECASE)
        self.SSO_URL = re.compile(self.config['sso_url'], re.IGNORECASE)
        if 'redirects' not in self.status:
            self.status['redirects'] = []

    def get_successful_responses(self, responses):
        return {url: urllib.unquote(response['headers'].get('location', ''))
                for url, response in responses.iteritems()
                if not response['code'] >= 400}

    def run(self):
        responses = self.get_all_my_domains_response()
        redirects = self.get_successful_responses(responses)

        old_redirects = self.status.get("redirects", {})
        alerts = {
            loc: redirect_url for loc, redirect_url in redirects.iteritems()
            if loc not in old_redirects or old_redirects[loc] != redirect_url
        }
        self.status["redirects"] = redirects
        for tested_url, location_header in alerts.iteritems():
            tested_url_domain_re = self.VALID_URL_RE.match(tested_url)

            if not tested_url_domain_re:
                self.logger.error('Invalid tested URL or location header: %s %s', tested_url, location_header)
            else:
                tested_domain = tested_url_domain_re.group(1)
                godauth_match = self.GODAUTH_URL.match(location_header)
                sso_match = self.SSO_URL.match(location_header)

                # full HTTPS site or redirects to SSO URLs
                if location_header.startswith('https://' + tested_domain) or \
                        (godauth_match and godauth_match.group(1) == tested_domain) or \
                        (sso_match and sso_match.group(1) == tested_domain):
                    continue

                yield {
                    "plugin_name": self.plugin_name,
                    "id": tested_url,
                    "details": list(
                        ["This domain (%s) is neither behind SSO nor GODAUTH because redirects to %s" % (
                            tested_url, location_header)])
                }


class SecurityHeaders(BaseClass):
    def __init__(self):
        self.plugin_name = 'security_headers'
        self.logger = logging.getLogger(self.plugin_name)

    def init(self, edda_client, config, status):
        self.edda_client = edda_client
        self.config = config
        self.status = status
        self.already_checked = self.status.setdefault('already_checked', [])

    def run(self):
        for location, response in self.get_all_my_domains_response().iteritems():
            if location not in self.already_checked and \
                    not response['headers'].get('x-frame-options') and 200 <= response['code'] < 300:
                self.already_checked.append(location)
                yield {
                    "plugin_name": self.plugin_name,
                    "id": location,
                    "details": list(["This webpage (%s) does not have X-Frame-Options header" % location])
                }
        self.status['already_checked'] = self.already_checked
