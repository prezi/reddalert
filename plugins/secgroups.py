#!/usr/bin/env python

import socket


class SecurityGroupPlugin:

    def __init__(self):
        self.plugin_name = 'secgroups'
        self.allowed_protocols = ["icmp"]
        self.allowed_ports = [22]
        self.suspicious_range = "0.0.0.0/0"

    def init(self, edda_client, config, status):
        self.edda_client = edda_client
        self.status = status
        if "allowed_protocols" in config:
            self.allowed_protocols = config["allowed_protocols"]
        if "allowed_ports" in config:
            self.allowed_ports = config["allowed_ports"]

    def run(self):
        return list(self.do_run())

    def do_run(self):
        groups = self.edda_client.updateonly().query("/api/v2/aws/securityGroups;_expand")
        machines = self.edda_client.query("/api/v2/view/instances;_expand")
        for group in groups:
            if group.get('vpcId', None):
                # ignore VPC security groups here, since we'll have a seperate plugin for those
                continue
            perms = list(self.suspicious_perms(group["ipPermissions"])) if "ipPermissions" in group else []
            if perms:
                affected_machines = self.machines_with_group(machines, group["groupId"])
                yield {
                    "plugin_name": self.plugin_name,
                    "id": '%s (%s)' % (group["groupId"], group["groupName"]),
                    "details": list(self.create_details(perms, affected_machines))
                }

    def machines_with_group(self, machines, groupId):
        return [machine for machine in machines if self.machine_in_group(machine, groupId)]

    def machine_in_group(self, machine, groupId):
        return "securityGroups" in machine and any([sg["groupId"] == groupId for sg in machine["securityGroups"]])

    def suspicious_perms(self, perms):
        for perm in perms:
            if self.is_suspicious(perm):
                yield perm

    def is_suspicious(self, perm):
        # fromPort and toPort defines a range for incoming connections
        # note: fromPort is not the peer's src port
        proto_ok = "ipProtocol" in perm and perm["ipProtocol"] in self.allowed_protocols
        iprange_nok = "ipRanges" in perm and self.suspicious_range in perm["ipRanges"]
        if (not proto_ok) and iprange_nok:
            f = int(perm["fromPort"] if "fromPort" in perm and perm["fromPort"] is not None else -1)
            t = int(perm["toPort"] if "toPort" in perm and perm["toPort"] is not None else 65536)
            return f != t or f not in self.allowed_ports
        return False

    def create_details(self, perms, machines):
        for perm in perms:
            mproc = [(m["instanceId"], m["publicIpAddress"], ",".join([t["value"] for t in m["tags"]]))
                     for m in machines]
            yield {
                'port_open': len(mproc) > 0 and self.is_port_open(mproc[0][1], perm['fromPort'], perm['toPort']),
                'machines': ["%s (%s): %s" % m for m in mproc],
                'fromPort': perm['fromPort'],
                'ipRanges': perm['ipRanges'],
                'toPort': perm['toPort'],
                'ipProtocol': perm['ipProtocol']
            }

    def is_port_open(self, host, port_from, port_to):
        if host and port_to and port_from and port_to >= 0 and port_to <= 65535 and port_from >= 0 and port_from <= 65535:
            if abs(port_to - port_from) > 20:
                return None
            for port_to_check in range(int(port_from), int(port_to) + 1):
                try:
                    print 'connecting'
                    # default timeout is 3 sec
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((host, port_to_check))
                    s.close()
                    return True
                except (socket.timeout, socket.error) as e:
                    print 'got exception', e
                    pass
        return False
