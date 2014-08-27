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
                instances = [{"tag": i["tag"], "started": i["started"], "machine": self.instance_enricher.enrich(i["machine"])}
                             for i in instances]
                yield {
                    "plugin_name": self.plugin_name,
                    "id": tag_name,
                    "details": [
                        {
                            "started": i["started"],
                            "instanceId": i["machine"].get("instanceId"),
                            "service_type": i["machine"].get("service_type"),
                            "elbs": i["machine"].get("elbs", []),
                            "open_ports": [sg["rules"] for sg in i["machine"].get("securityGroups", [])]
                        } for i in instances
                    ]
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
        suspicious_machines = [self.instance_enricher.enrich(m) for m in machines if self.is_suspicious(m, since)]

        for machine in suspicious_machines:
            yield {
                "plugin_name": self.plugin_name,
                "id": machine.get("instanceId"),
                "details": [self.generate_details(machine)]
            }

    def is_suspicious(self, machine, since):
        tags = [t["value"] for t in machine["tags"] if t["key"] == "service_name"]
        return int(machine["launchTime"]) > since and len(tags) == 0

    def generate_details(self, instance):
        return {
            "instanceId": instance.get("instanceId"),
            "started": int(instance.get("launchTime")),
            "service_type": instance.get("service_type"),
            "elbs": instance.get("elbs"),
            "open_ports": [sg["rules"] for sg in instance.get("securityGroups", [])]
        }