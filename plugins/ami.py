#!/usr/bin/env python

from api import InstanceEnricher

class NewAMIPlugin:

    def __init__(self):
        self.plugin_name = 'ami'

    def init(self, edda_client, config, status, instance_enricher):
        self.edda_client = edda_client
        self.allowed_services = config["allowed_tags"] if "allowed_tags" in config else []
        self.instance_enricher = instance_enricher
        self.initialize_status(status)

    def initialize_status(self, status):
        if 'first_seen' not in status:
            status['first_seen'] = {}
        self.status = status

    def run(self):
        return list(self.do_run())

    def is_blacklisted(self, machine):
        return machine.get("service_type") in self.allowed_services

    def generate_details(self, machines):
        for instanceId, started, machine in machines:
            self.instance_enricher.enrich(machine)
            yield {
                "instanceId": instanceId,
                "started": started,
                "service_type": machine["service_type"],
                "elbs": machine.get("elbs"),
                "open_ports": [sg["rules"] for sg in machine.get("securityGroups", [])]
            }

    def do_run(self):
        since = self.edda_client._since if self.edda_client._since is not None else 0
        machines = self.edda_client.soft_clean().query("/api/v2/view/instances;_expand")

        grouped_by_ami = {}
        for m in machines:
            grouped_by_ami.setdefault(m["imageId"], []).append((m["instanceId"],
                                                                int(m["launchTime"]),
                                                                self.instance_enricher.enrich(m)))

        first_seen = {imageId: min([i[1] for i in instances]) for imageId, instances in grouped_by_ami.iteritems()}
        first_seen_updates = {imageId: min(first_seen[imageId], launchTime) if imageId in first_seen else launchTime
                              for imageId, launchTime in self.status['first_seen'].iteritems()}
        first_seen.update(first_seen_updates)
        self.status['first_seen'] = dict(first_seen)

        for ami_id, instances in grouped_by_ami.iteritems():
            if first_seen[ami_id] >= since:
                new_machines = [i for i in instances if i[1] >= since and not self.is_blacklisted(i[2])]
                if len(new_machines) > 0:
                    details = list(self.generate_details(new_machines))
                    yield {
                        "plugin_name": self.plugin_name,
                        "id": ami_id,
                        "details": details
                    }
