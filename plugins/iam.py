#!/usr/bin/env python
import re
import pprint
from api.eddaclient import EddaException


class UserAddedPlugin:

    def __init__(self):
        self.plugin_name = 'iam'

    def init(self, edda_client, config, status):
        self.edda_client = edda_client
        self.status = status
        self.config = config
        self.pp = pprint.PrettyPrinter(indent=4)
        self.allowed = self.init_allowed_list_cache()

    def init_allowed_list_cache(self):
        return list(re.compile(allowed) for allowed in self.config['allowed']) if 'allowed' in self.config else []

    def run(self):
        return list(self.do_run())

    def do_run(self):
        users = self.edda_client.updateonly().query("/api/v2/aws/iamUsers")
        # a user might have changed several times, but
        # we want to look them up only once
        modifed_users = list(set(users))

        for username in modifed_users:
            # skip allowed users
            if any(regex.match(username) for regex in self.allowed):
                continue
            details = []
            try:
                diff = self.edda_client.raw_query("/api/v2/aws/iamUsers/%s;_diff=200" % username)
                # find group changes in diff
                m = re.findall(r'"groups" : \[([^\]]+)\]', diff)
                if m:
                    added = []
                    removed = []
                    for match in m:
                        for group in match.strip().split('\n'):
                            stripped = group[1:].strip(' ",')
                            if stripped and group[0] == '+':
                                added.append(stripped)
                            elif stripped and group[0] == '-':
                                removed.append(stripped)
                    if added:
                        # alert on group addon
                        details.append('Groups the user has been added to: %s' % ', '.join(added))
            except EddaException as e:
                # print repr(e)
                if e.response['code'] == 400 and e.response['message'] == '_diff requires at least 2 documents, only 1 found':
                    print 'Got error 400, don\'t worry, we\'re fetching user detail without diffing then.'
                    user_object = self.pp.pformat(
                        self.edda_client.updateonly().query("/api/v2/aws/iamUsers/%s" % username))
                    # alert on user addon
                    details.append('New user has been added: %s\n' % user_object)
#            except Exception as e:
#                print 'Got unexpected exception: ', repr(e)

            if details:
                yield {
                    "plugin_name": self.plugin_name,
                    "id": username,
                    "details": details
                }
