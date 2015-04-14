from ami import NewAMIPlugin
from elbs import ElasticLoadBalancerPlugin
from iam import UserAddedPlugin
from instancetags import MissingInstanceTagPlugin, NewInstanceTagPlugin
from s3acl import S3AclPlugin
from secgroups import SecurityGroupPlugin
from chef import NonChefPlugin
from route53 import Route53Unknown, Route53Changed
from sso import SSOUnprotected


plugin_list = {
    'secgroups': SecurityGroupPlugin(),
    'ami': NewAMIPlugin(),
    'elbs': ElasticLoadBalancerPlugin(),
    'newtag': NewInstanceTagPlugin(),
    'missingtag': MissingInstanceTagPlugin(),
    'iam': UserAddedPlugin(),
    's3acl': S3AclPlugin(),
    'non_chef': NonChefPlugin(),
    'route53unknown': Route53Unknown(),
    'route53changed': Route53Changed(),
    'sso_unprotected': SSOUnprotected()
}
