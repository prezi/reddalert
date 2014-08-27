import unittest
from mock import Mock

from api.instanceenricher import InstanceEnricher

class InstanceEnricherTestCase(unittest.TestCase):

    def setUp(self):
        self.edda_client = Mock()
        edda_outer = Mock()
        edda_outer.soft_clean = Mock(return_value=self.edda_client)
        self.instance_enricher = InstanceEnricher(edda_outer)

    def test_query_securitygroups(self):
        SECURITY_GROUPS = [
            {
                "vpcId": None,
                "class": "com.amazonaws.services.ec2.model.SecurityGroup",
                "description": "security-log-source",
                "groupId": "sg-XXXXX1",
                "groupName": "security-log-source",
                "ipPermissions": [
                    {
                        "userIdGroupPairs": [],
                        "toPort": 22,
                        "ipRanges": [
                            "0.0.0.0/0"
                        ],
                        "ipProtocol": "tcp",
                        "fromPort": 22,
                        "class": "com.amazonaws.services.ec2.model.IpPermission"
                    }
                ],
                "ipPermissionsEgress": [],
                "ownerId": "123",
                "tags": []
            },
            {
                "vpcId": None,
                "class": "com.amazonaws.services.ec2.model.SecurityGroup",
                "description": "security-log-drain",
                "groupId": "sg-XXXXX2",
                "groupName": "security-log-drain",
                "ipPermissions": [
                    {
                        "userIdGroupPairs": [],
                        "toPort": 22,
                        "ipRanges": [
                            "0.0.0.0/0"
                        ],
                        "ipProtocol": "tcp",
                        "fromPort": 22,
                        "class": "com.amazonaws.services.ec2.model.IpPermission"
                    },
                    {
                        "userIdGroupPairs": [],
                        "toPort": 22,
                        "ipRanges": [
                            "10.1.0.0/16",
                            "192.168.0.0/16",
                        ],
                        "ipProtocol": "tcp",
                        "fromPort": 22,
                        "class": "com.amazonaws.services.ec2.model.IpPermission"
                    }
                ],
                "ipPermissionsEgress": [],
                "ownerId": "123",
                "tags": []
            },
        ]
        self.edda_client.query = Mock(return_value=SECURITY_GROUPS)

        sgs = self.instance_enricher._query_security_groups()

        self.assertIsInstance(sgs, dict)
        self.assertIn("sg-XXXXX1", sgs)
        self.assertIn("sg-XXXXX2", sgs)
        self.assertEqual(3, len(sgs["sg-XXXXX2"]))

    def test_enrich(self):
        self.instance_enricher.elbs = [
            {"DNSName": "foo.prezi.com", "instances": ["A", "B"], "ports": ["80", "81"]},
            {"DNSName": "bar.prezi.com", "instances": ["A", "C"], "ports": ["80", "81"]}
        ]
        self.instance_enricher.sec_groups = {
            "sg-XXXXX1": [{"port": "22", "range": "0.0.0.0/0"}]
        }
        INSTANCE_DATA = {
            "tags": [
                {
                    "value": "lucid",
                    "maksim_node_type": "lucid",
                    "key": "maksim_node_type",
                    "class": "com.amazonaws.services.ec2.model.Tag"
                },
                {
                    "value": "jenkins",
                    "service_name": "jenkins",
                    "key": "service_name",
                    "class": "com.amazonaws.services.ec2.model.Tag"
                }
            ],
            "instanceId": "A",
            "securityGroups": [
                {
                    "groupName": "jenkins",
                    "groupId": "sg-XXXXX1",
                    "class": "com.amazonaws.services.ec2.model.GroupIdentifier"
                }
            ]
        }

        self.instance_enricher.enrich(INSTANCE_DATA)

        self.assertIn("elbs", INSTANCE_DATA)
        self.assertEqual(2, len(INSTANCE_DATA["elbs"]))
        self.assertIn("rules", INSTANCE_DATA["securityGroups"][0])
        self.assertEqual(1, len(INSTANCE_DATA["securityGroups"][0]["rules"]))
        self.assertEqual("jenkins", INSTANCE_DATA["service_type"])
