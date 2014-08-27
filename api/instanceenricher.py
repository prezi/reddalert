import operator

class InstanceEnricher:

    def __init__(self, edda_client):
        self.edda_client = edda_client.soft_clean()
        self.elbs = []
        self.sec_groups = {}

    def initialize_caches(self):
        self.elbs = self._query_loadbalancers()
        self.sec_groups = self._query_security_groups()

    def _query_security_groups(self):
        groups = self.edda_client.query("/api/v2/aws/securityGroups;_expand")
        return {g["groupId"]: reduce(operator.add, self._clean_ip_permissions(g["ipPermissions"]), []) for g in groups}

    def _clean_ip_permissions(self, perms):
        return [self._clean_ip_permission(p) for p in perms]

    def _clean_ip_permission(self, permission):
        return [{"port": permission["toPort"], "range": r} for r in permission["ipRanges"]]

    def _query_loadbalancers(self):
        elbs = self.edda_client.query("/api/v2/aws/loadBalancers;_expand")
        return [self._clean_elb(e) for e in elbs if len(e.get("instances", [])) > 0]

    def _clean_elb(self, elb):
        return {
            "DNSName": elb.get("DNSName"),
            "instances": [i.get("instanceId") for i in elb.get("instances")],
            "ports": [l.get("listener", {}).get("loadBalancerPort") for l in elb.get("listenerDescriptions")]
        }

    def enrich(self, instance_data):
        instance_id = instance_data.get("instanceId")
        instance_data["service_type"] = self._get_type_from_tags(instance_data.get("tags", [])) or instance_id
        instance_data["elbs"] = [elb for elb in self.elbs if instance_id in elb["instances"]]
        self._enrich_security_groups(instance_data)
        return instance_data

    def _enrich_security_groups(self, instance_data):
        if "securityGroups" in instance_data:
            for sg in instance_data["securityGroups"]:
                sg["rules"] = self.sec_groups.get(sg["groupId"], [])

    def _get_type_from_tags(self, tags):
        LOOKUP_ORDER = ["service_name", "Name", "aws:autoscaling:groupName"]
        for tag_name in LOOKUP_ORDER:
            for tag in tags:
                if tag.get("key") == tag_name:
                    return tag.get("value")
        return None

    def report(self, instance_data, extra={}):
        return instance_report(self.enrich(instance_data), extra)


def instance_report(instance, extra={}):
    result = {
        "instanceId": instance.get("instanceId", None),
        "started": int(instance.get("launchTime", 0)),
        "service_type": instance.get("service_type", None),
        "elbs": instance.get("elbs", []),
        "open_ports": [sg["rules"] for sg in instance.get("securityGroups", [])],
        "publicIpAddress": instance.get("publicIpAddress", None),
        "privateIpAddress": instance.get("privateIpAddress", None)
    }
    result.update(extra)
    return result