#!/usr/bin/env python
import itertools

class NewInstanceTagPlugin:

    def __init__(self):
        self.plugin_name = 'newtag'

    def init(self, edda_client, config, status, instance_enricher):
        self.edda_client = edda_client
        self.status = status
        self.config = config
        self.instance_enricher = instance_enricher

    def run(self):
        return list(self.do_run())

    def do_run(self):
        machines = self.edda_client.clean().query("/api/v2/view/instances;_expand")
        since = self.edda_client._since if self.edda_client._since is not None else 0
        tags = [{"tag": t["value"], "started": int(m["launchTime"]), "machine": m}
                for m in machines
                for t in m["tags"] if t["key"] == "service_name"]
        grouped_by_tag = itertools.groupby(sorted(tags, key=lambda e: e["tag"]), key=lambda e: e["tag"])

        for tag_name, instances in grouped_by_tag:
            instances = list(instances)
            if all([i["started"] >= since for i in instances]):
                yield {
                    "plugin_name": self.plugin_name,
                    "id": tag_name,
                    "details": [self.instance_enricher.report(i["machine"]) for i in instances]
                }


class MissingInstanceTagPlugin:

    def __init__(self):
        self.plugin_name = 'missingtag'

    def init(self, edda_client, config, status, instance_enricher):
        self.edda_client = edda_client
        self.status = status
        self.config = config
        self.instance_enricher = instance_enricher

    def run(self):
        return list(self.do_run())

    def do_run(self):
        machines = self.edda_client.clean().query("/api/v2/view/instances;_expand")
        since = self.edda_client._since if self.edda_client._since is not None else 0
        suspicious_machines = [m for m in machines if self.is_suspicious(m, since)]
        for machine in suspicious_machines:
            yield {
                "plugin_name": self.plugin_name,
                "id": machine.get("instanceId"),
                "details": [self.instance_enricher.report(machine)]
            }

    def is_suspicious(self, machine, since):
        tags = [t["value"] for t in machine["tags"] if t["key"] == "service_name"]
        return int(machine["launchTime"]) > since and len(tags) == 0
