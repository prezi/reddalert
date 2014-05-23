from ami import NewAMIPlugin
from elbs import ElasticLoadBalancerPlugin
from iam import UserAddedPlugin
from instancetags import MissingInstanceTagPlugin, NewInstanceTagPlugin
from s3acl import S3AclPlugin
from secgroups import SecurityGroupPlugin
from chef import NonChefPlugin


plugin_list = {
    'secgroups': SecurityGroupPlugin(),
    'ami': NewAMIPlugin(),
    'elbs': ElasticLoadBalancerPlugin(),
    'newtag': NewInstanceTagPlugin(),
    'missingtag': MissingInstanceTagPlugin(),
    'iam': UserAddedPlugin(),
    's3acl': S3AclPlugin(),
    'non_chef': NonChefPlugin()
}
