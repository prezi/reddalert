#!/usr/bin/env python

import socket
import string


class SecurityGroupPlugin:
    def __init__(self):
        self.plugin_name = 'secgroups'
        self.allowed_protocols = ["icmp"]
        self.allowed_ports = []
        self.whitelisted_ips = []
        self.whitelisted_entries = {}

    def init(self, edda_client, config, status):
        self.edda_client = edda_client
        self.status = status
        if "allowed_protocols" in config:
            self.allowed_protocols = config["allowed_protocols"]
        if "allowed_ports" in config:
            self.allowed_ports = config["allowed_ports"]
        if "whitelisted_entries" in config:
            self.whitelisted_entries = config["whitelisted_entries"]
        if "whitelisted_ips" in config:
            self.whitelisted_ips = config["whitelisted_ips"]
            for i, ip in enumerate(self.whitelisted_ips):
                if '/' not in ip:
                    self.whitelisted_ips[i] = '{ip}/32'.format(ip=ip)

    def run(self):
        return list(self.do_run())

    def do_run(self):
        groups = self.edda_client.updateonly().query("/api/v2/aws/securityGroups;_expand")
        machines = self.edda_client.query("/api/v2/view/instances;_expand")
        for security_group in groups:
            perms = list(self.suspicious_perms(security_group))
            if perms:
                yield {
                    "plugin_name": self.plugin_name,
                    "id": '%s (%s)' % (security_group["groupId"], security_group["groupName"]),
                    "details": list(self.create_details(perms, machines, security_group))
                }

    def machines_with_group(self, machines, groupId):
        return [machine for machine in machines if self.machine_in_group(machine, groupId)]

    def machine_in_group(self, machine, groupId):
        return "securityGroups" in machine and any([sg["groupId"] == groupId for sg in machine["securityGroups"]])

    def is_whitelisted_perm(self, security_group, perm):
        port = str(perm["fromPort"]) if perm["fromPort"] == perm["toPort"] else '{fromPort}-{toPort}'.format(
            fromPort=perm["fromPort"], toPort=perm["toPort"])
        entry_name = '{sg_id} ({sg_name})'.format(sg_id=security_group["groupId"], sg_name=security_group["groupName"])
        whitelisted_ip_ranges = self.whitelisted_entries.get(entry_name, {}).get(port, [])
        return bool(whitelisted_ip_ranges and all(
            [actual_ip_range in whitelisted_ip_ranges for actual_ip_range in perm.get("ipRanges", [])]))

    def suspicious_perms(self, security_group):
        perms = security_group.get("ipPermissions", [])
        for perm in perms:
            if not self.is_whitelisted_perm(security_group, perm) and self.is_suspicious_permission(perm):
                yield perm

    def is_suspicious_ip_range(self, ip_range):
        # TODO: handle subsets of IP ranges as well
        return ip_range not in self.whitelisted_ips

    def is_suspicious_permission(self, perm):
        # fromPort and toPort defines a range for incoming connections
        # note: fromPort is not the peer's src port
        proto_ok = "ipProtocol" in perm and perm["ipProtocol"] in self.allowed_protocols
        iprange_nok = "ipRanges" in perm and any(
            [self.is_suspicious_ip_range(ip_range) for ip_range in perm["ipRanges"]])
        if (not proto_ok) and iprange_nok:
            f = int(perm["fromPort"] if "fromPort" in perm and perm["fromPort"] is not None else -1)
            t = int(perm["toPort"] if "toPort" in perm and perm["toPort"] is not None else 65536)
            # allowing port range is considered to be suspicious
            return f != t or f not in self.allowed_ports
        return False

    def create_details(self, perms, machines, group):
        affected_machines = self.machines_with_group(machines, group["groupId"])
        aws_availability_zone = '' if not affected_machines else affected_machines[0]['placement']['availabilityZone']
        aws_region = aws_availability_zone.rstrip(string.ascii_lowercase)
        aws_account = group['ownerId']
        for perm in perms:
            mproc = [(m["instanceId"], m["publicIpAddress"] or m["privateIpAddress"],
                      ",".join([t["value"] for t in m["tags"]]))
                     for m in affected_machines]
            yield {
                'port_open': len(mproc) > 0 and self.is_port_open(mproc[0][1], perm['fromPort'], perm['toPort']),
                'ipAddresses': [m[1] for m in mproc if m[1]],
                'machines': ["%s (%s): %s" % m for m in mproc],
                'fromPort': perm['fromPort'],
                'ipRanges': perm['ipRanges'],
                'toPort': perm['toPort'],
                'ipProtocol': perm['ipProtocol'],
                'awsRegion': aws_region,
                'awsAccount': aws_account
            }

    def is_port_open(self, host, port_from, port_to):
        if host and port_to and port_from and 0 <= port_to <= 65535 and 0 <= port_from <= 65535:
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
