import unittest
from mock import Mock, patch

from api.instanceenricher import InstanceEnricher


class InstanceEnricherTestCase(unittest.TestCase):
    def setUp(self):
        self.edda_client = Mock()
        edda_outer = Mock()
        edda_outer.soft_clean = Mock(return_value=self.edda_client)
        self.instance_enricher = InstanceEnricher(edda_outer)

        self.mock_instance_data = {
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
            "iamInstanceProfile": {'arn': 'arn:aws:iam::783721547467:instance-profile/dummyservice'},
            'placement': {'availabilityZone': 'us-east-1b'},
            'launchTime': 1234,
            'privateIpAddress': '1.2.3.4',
            'publicIpAddress': '10.20.30.40',
            "securityGroups": [
                {
                    "groupName": "jenkins",
                    "groupId": "sg-XXXXX1",
                    "class": "com.amazonaws.services.ec2.model.GroupIdentifier"
                }
            ]
        }
        self.mock_instance_enrich_elbs = [
            {"DNSName": "foo.prezi.com", "instances": ["A", "B"], "ports": ["80", "81"]},
            {"DNSName": "bar.prezi.com", "instances": ["A", "C"], "ports": ["80", "81"]}
        ]
        self.mock_instance_enrich_secgroups = {"sg-XXXXX1": [{"port": "22", "range": "0.0.0.0/0"}]}

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
            "iamInstanceProfile": None,
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

    @patch('api.instanceenricher.InstanceEnricher._clean_ip_permissions', return_value=[])
    def test_empty_secgroup_query(self, *mocks):
        self.edda_client.query = Mock(
            return_value=[{"ipPermissions": [{"ipRanges": ['1', '2'], "toPort": '22'}], "groupId": "G"}])
        self.assertEqual([], self.instance_enricher._clean_ip_permissions([{"ipRanges": [], "toPort": None}]))
        self.assertEquals({"G": []}, self.instance_enricher._query_security_groups())  # shall not throw exception

    def test_tag_extraction(self):
        tags = [
            {
                "value": "nessus",
                "key": "Name",
                "class": "com.amazonaws.services.ec2.model.Tag",
                "Name": "nessus"
            },
            {
                "value": "nessus",
                "service_name": "nessus",
                "key": "service_name",
                "class": "com.amazonaws.services.ec2.model.Tag"
            }
        ]
        name = self.instance_enricher._get_type_from_tags(tags)
        self.assertEqual("nessus", name)

    def test_instance_report(self):
        self.instance_enricher.elbs = self.mock_instance_enrich_elbs
        self.instance_enricher.sec_groups = self.mock_instance_enrich_secgroups
        self.instance_enricher.enrich(self.mock_instance_data)

        report = self.instance_enricher.report(self.mock_instance_data, {'dummy_extra_key': 'dummy_extra_value'})
        self.assertItemsEqual(report.keys(), ['privateIpAddress', 'service_type', 'publicIpAddress', 'elbs',
                                              'instanceId', 'awsRegion', 'awsAccount', 'keyName', 'dummy_extra_key',
                                              'open_ports', 'started', 'tags'
                                              ])
        self.assertEqual(report['awsAccount'], '783721547467')
        self.assertEqual(report['awsRegion'], 'us-east-1')
        self.assertEqual(report['started'], 1234)
        self.assertEqual(report['dummy_extra_key'], 'dummy_extra_value')
        self.assertEqual(report['privateIpAddress'], '1.2.3.4')
        self.assertEqual(report['publicIpAddress'], '10.20.30.40')
        self.assertEqual(report['service_type'], 'jenkins')
        self.assertEqual(report['instanceId'], 'A')

    def test_instance_report_no_profile(self):
        self.mock_instance_data['iamInstanceProfile'] = None
        self.instance_enricher.elbs = self.mock_instance_enrich_elbs
        self.instance_enricher.sec_groups = self.mock_instance_enrich_secgroups
        self.instance_enricher.enrich(self.mock_instance_data)

        report = self.instance_enricher.report(self.mock_instance_data, {'dummy_extra_key': 'dummy_extra_value'})
        self.assertIsNone(report['awsAccount'])
