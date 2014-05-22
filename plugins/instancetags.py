#!/usr/bin/env python


class NewInstanceTagPlugin:

    def __init__(self):
        self.plugin_name = 'newtag'

    def init(self, edda_client, config, status):
        self.edda_client = edda_client
        self.status = status
        self.config = config

    def run(self):
        return list(self.do_run())

    def do_run(self):
        machines = self.edda_client.clean().query("/api/v2/view/instances;_expand")
        since = self.edda_client._since if self.edda_client._since is not None else 0
        tags = [(t["value"], m["instanceId"], int(m["launchTime"]))
                for m in machines
                for t in m["tags"] if t["key"] == "service_name"]
        tagnames = set([t[0] for t in tags])
        grouped_by_tag = {tn: [] for tn in tagnames}
        for t in tags:
            grouped_by_tag[t[0]].append(t)

        for tag_name, instances in grouped_by_tag.iteritems():
            if all([i[2] >= since for i in instances]):
                yield {
                    "plugin_name": self.plugin_name,
                    "id": tag_name,
                    "details": [", ".join([i[1] for i in instances])]
                }


class MissingInstanceTagPlugin:

    def __init__(self):
        self.plugin_name = 'missingtag'

    def init(self, edda_client, config, status):
        self.edda_client = edda_client
        self.status = status
        self.config = config

    def run(self):
        return list(self.do_run())

    def do_run(self):
        machines = self.edda_client.clean().query("/api/v2/view/instances;_expand")
        since = self.edda_client._since if self.edda_client._since is not None else 0
        fmach = [m["instanceId"] for m in machines if self.is_suspicious(m, since)]

        for instanceName in fmach:
            yield {
                "plugin_name": self.plugin_name,
                "id": instanceName,
                "details": ["n/a"]
            }

    def is_suspicious(self, machine, since):
        tags = [t["value"] for t in machine["tags"] if t["key"] == "service_name"]
        return int(machine["launchTime"]) > since and len(tags) == 0
