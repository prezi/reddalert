#!/usr/bin/env python


class NewAMIPlugin:

    def __init__(self):
        self.plugin_name = 'ami'

    def init(self, edda_client, config, status):
        self.edda_client = edda_client
        self.allowed_services = config["allowed_tags"] if "allowed_tags" in config else []
        self.initialize_status(status)

    def initialize_status(self, status):
        if 'first_seen' not in status:
            status['first_seen'] = {}
        self.status = status

    def run(self):
        return list(self.do_run())

    def is_blacklisted(self, tags):
        for t in tags:
            if 'service_name' in t and t['service_name'] in self.allowed_services:
                return True
        return False

    def do_run(self):
        since = self.edda_client._since if self.edda_client._since is not None else 0
        machines = self.edda_client.clean().query("/api/v2/view/instances;_expand")

        keys = set([m["imageId"] for m in machines])
        grouped_by_ami = {}
        for m in machines:
            grouped_by_ami.setdefault(m["imageId"], []).append(
                (m["instanceId"], int(m["launchTime"]),
                    [{t["key"]: t["value"]} for t in m["tags"] if t["key"] in ["service_name", 'started_by']]
                    if "tags" in m else []))

        first_seen = {imageId: min([i[1] for i in instances]) for imageId, instances in grouped_by_ami.iteritems()}
        first_seen_updates = {imageId: min(first_seen[imageId], launchTime) if imageId in first_seen else launchTime
                              for imageId, launchTime in self.status['first_seen'].iteritems()}
        first_seen.update(first_seen_updates)
        self.status['first_seen'] = dict(first_seen)

        # print grouped_by_ami, first_seen, since
        for ami_id, instances in grouped_by_ami.iteritems():
            if first_seen[ami_id] >= since:
                details = [i for i in instances if i[1] >= since and not self.is_blacklisted(i[2])]
                if len(details) > 0:
                    yield {
                        "plugin_name": self.plugin_name,
                        "id": ami_id,
                        "details": details
                    }
