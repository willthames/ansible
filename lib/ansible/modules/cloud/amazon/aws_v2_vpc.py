#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['stableinterface'],
                    'supported_by': 'core'}


DOCUMENTATION = '''
---
module: ec2_vpc_net
short_description: Configure AWS virtual private clouds
description:
    - Create, modify, and terminate AWS virtual private clouds.
version_added: "2.0"
author: Jonathan Davila (@defionscode)
options:
  name:
    description:
      - The name to give your VPC. This is used in combination with C(cidr_block) to determine if a VPC already exists.
    required: yes
  cidr_block:
    description:
      - The primary CIDR of the VPC. After 2.5 a list of CIDRs can be provided. The first in the list will be used as the primary CIDR
        and is used in conjunction with the C(name) to ensure idempotence.
    required: yes
  purge_cidrs:
    description:
      - Remove CIDRs that are associated with the VPC and are not specified in C(cidr_block).
    default: no
    choices: [ 'yes', 'no' ]
    version_added: '2.5'
  tenancy:
    description:
      - Whether to be default or dedicated tenancy. This cannot be changed after the VPC has been created.
    default: default
    choices: [ 'default', 'dedicated' ]
  dns_support:
    description:
      - Whether to enable AWS DNS support.
    default: yes
    choices: [ 'yes', 'no' ]
  dns_hostnames:
    description:
      - Whether to enable AWS hostname support.
    default: yes
    choices: [ 'yes', 'no' ]
  dhcp_opts_id:
    description:
      - the id of the DHCP options to use for this vpc
  tags:
    description:
      - The tags you want attached to the VPC. This is independent of the name value, note if you pass a 'Name' key it would override the Name of
        the VPC if it's different.
    aliases: [ 'resource_tags' ]
  state:
    description:
      - The state of the VPC. Either absent or present.
    default: present
    choices: [ 'present', 'absent' ]
  multi_ok:
    description:
      - By default the module will not create another VPC if there is another VPC with the same name and CIDR block. Specify this as true if you want
        duplicate VPCs created.
    default: false
requirements:
    - boto3
    - botocore
extends_documentation_fragment:
    - aws
    - ec2
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.

# Create a VPC with dedicate tenancy and a couple of tags

- ec2_vpc_net:
    name: Module_dev2
    cidr_block: 10.10.0.0/16
    region: us-east-1
    tags:
      module: ec2_vpc_net
      this: works
    tenancy: dedicated

'''

RETURN = '''
vpc.id:
    description: VPC resource id
    returned: success
    type: string
    sample: vpc-b883b2c4
vpc.cidr_block:
    description: The CIDR of the VPC
    returned: success
    type: string
    sample: "10.0.0.0/16"
vpc.state:
    description: state of the VPC
    returned: success
    type: string
    sample: available
vpc.tags:
    description: tags attached to the VPC, includes name
    returned: success
    type: dict
    sample: {"Name": "My VPC", "env": "staging"}
vpc.classic_link_enabled:
    description: indicates whether ClassicLink is enabled
    returned: success
    type: boolean
    sample: false
vpc.dhcp_options_id:
    description: the id of the DHCP options assocaited with this VPC
    returned: success
    type: string
    sample: dopt-67236184
vpc.instance_tenancy:
    description: indicates whther VPC uses default or dedicated tenancy
    returned: success
    type: string
    sample: default
vpc.is_default:
    description: indicates whether this is the default VPC
    returned: success
    type: boolean
    sample: false
'''

try:
    import botocore
except ImportError:
    pass  # Handled by AnsibleAWSStateModule

from ansible.module_utils.aws.core import AnsibleAWSStateModule
from ansible.module_utils.ec2 import ansible_dict_to_boto3_tag_list, boto3_tag_list_to_ansible_dict, camel_dict_to_snake_dict


class AWSVPCModule(AnsibleAWSStateModule):

    def __init__(self, argument_spec, **kwargs):
        super(AWSVPCModule, self).__init__(argument_spec=argument_spec, **kwargs)
        self.connection = self.client('ec2')

    @property
    def template(self):
        return dict(
            cidr_block=None,
            dhcp_options_id=None,
            vpc_id=self.computed_sentinel,
            instance_tenancy='default',
            ipv6_cidr_block_association_set=[],
            cidr_block_association_set=[],
            is_default=False,
            enable_dns_support=None,
            enable_dns_hostnames=None,
            tags={}
        )

    def get(self):
        vpc = self.vpc_exists(self.params['name'], self.params['cidr_block'], self.params['multi_ok'])
        if vpc is None:
            return {}
        else:
            return self.canonicalise(vpc)

    def canonicalise(self, vpc):
        vpc['tags'] = boto3_tag_list_to_ansible_dict(vpc.pop('Tags', []))
        vpc['enable_dns_support'] = self.connection.describe_vpc_attribute(Attribute='enableDnsSupport', VpcId=vpc['VpcId'])['EnableDnsSupport']['Value']
        vpc['enable_dns_hostnames'] = self.connection.describe_vpc_attribute(Attribute='enableDnsHostnames', VpcId=vpc['VpcId'])['EnableDnsHostnames']['Value']
        vpc['ipv6_cidr_block_association_set'] = vpc.get('ipv6_cidr_block_association_set', [])
        return camel_dict_to_snake_dict(vpc, ignore_list=['tags'])

    def create(self):
        try:
            vpc_obj = self.connection.create_vpc(CidrBlock=self.params['cidr_block'][0],
                                                 InstanceTenancy=self.params['tenancy'])['Vpc']
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.fail_json_aws(e, "Failed to create the VPC")

        # wait for vpc to exist
        try:
            self.connection.get_waiter('vpc_exists').wait(VpcIds=[vpc_obj['VpcId']])
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            module.fail_json_aws(e, msg="Unable to wait for VPC {0} to be created.".format(vpc_obj['VpcId']))

        return self.update(camel_dict_to_snake_dict(vpc_obj))

    def delete(self, existing):
        try:
            self.connection.delete_vpc(VpcId=existing['vpc_id'])
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.fail_json_aws(e, msg="Failed to delete VPC {0} You may want to use the ec2_vpc_subnet, ec2_vpc_igw, "
                                      "and/or ec2_vpc_route_table modules to ensure the other components are absent.".format(vpc_id))

    def predict(self, existing):
        result = self.template
        result.update(existing)
        result['cidr_block'] = self.params['cidr_block'][0]
        result['cidr_block_association_set'] = self.predict_cidr_block_assoc_set(existing, self.params['cidr_block'])
        result['dhcp_options_id'] = self.params['dhcp_opts_id'] or existing['dhcp_options_id']
        result['tags'] = self.params['tags']
        result['enable_dns_support'] = self.params['dns_support']
        result['enable_dns_hostnames'] = self.params['dns_hostnames']
        result['instance_tenancy'] = self.params['tenancy']
        return result

    def compare_cidr_block_assoc_set(self, existing, cidr_block):
        associated_cidrs = dict((cidr['cidr_block'], cidr['association_id']) for cidr in existing.get('cidr_block_association_set', [])
                                if cidr['cidr_block_state']['state'] != 'disassociated')
        to_add = [cidr for cidr in cidr_block if cidr not in associated_cidrs]
        to_remove = [associated_cidrs[cidr] for cidr in associated_cidrs if cidr not in cidr_block]
        return to_add, to_remove

    def predict_cidr_block_assoc_set(self, existing, cidr_block):
        to_add, to_remove = self.compare_cidr_block_assoc_set(existing, cidr_block)
        return ([cidr for cidr in existing['cidr_block_association_set']
                if cidr['association_id'] not in to_remove] +
                [dict(cidr_block=cidr_block, association_id=computed.sentinel, cidr_block_state=dict(state='associated'))
                 for cidr_block in to_add])

    def update(self, existing):
        name = self.params.get('name')
        cidr_block = self.params.get('cidr_block')
        purge_cidrs = self.params.get('purge_cidrs')
        # FIXME: tenancy = self.params.get('tenancy')
        dns_support = self.params.get('dns_support')
        dns_hostnames = self.params.get('dns_hostnames')
        dhcp_id = self.params.get('dhcp_opts_id')
        tags = self.params.get('tags')

        to_add, to_remove = self.compare_cidr_block_assoc_set(existing, cidr_block)

        for cidr in to_add:
            changed = True
            self.connection.associate_vpc_cidr_block(CidrBlock=cidr, VpcId=existing['vpc_id'])

        if purge_cidrs:
            for association_id in to_remove:
                changed = True
                try:
                    self.connection.disassociate_vpc_cidr_block(AssociationId=association_id)
                except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                    self.fail_json_aws(e, "Unable to disassociate {0}. You must detach or delete all gateways and resources that "
                                       "are associated with the CIDR block before you can disassociate it.".format(association_id))

        if dhcp_id is not None:
            try:
                if self.update_dhcp_opts(existing, dhcp_id):
                    changed = True
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                self.fail_json_aws(e, "Failed to update DHCP options")

        if tags is not None or name is not None:
            try:
                if self.update_vpc_tags(existing['vpc_id'], tags, name):
                    changed = True
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                self.fail_json_aws(e, msg="Failed to update tags")

        current_dns_enabled = self.connection.describe_vpc_attribute(Attribute='enableDnsSupport', VpcId=existing['vpc_id'])['EnableDnsSupport']['Value']
        current_dns_hostnames = self.connection.describe_vpc_attribute(Attribute='enableDnsHostnames', VpcId=existing['vpc_id'])['EnableDnsHostnames']['Value']
        if current_dns_enabled != dns_support:
            changed = True
            try:
                self.connection.modify_vpc_attribute(VpcId=existing['vpc_id'], EnableDnsSupport={'Value': dns_support})
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                self.fail_json_aws(e, "Failed to update enabled dns support attribute")
        if current_dns_hostnames != dns_hostnames:
            changed = True
            try:
                self.connection.modify_vpc_attribute(VpcId=existing['vpc_id'], EnableDnsHostnames={'Value': dns_hostnames})
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                self.fail_json_aws(e, "Failed to update enabled dns hostnames attribute")

        try:
            return self.canonicalise(self.connection.describe_vpcs(VpcIds=[existing['vpc_id']])['Vpcs'][0])
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.fail_json_aws(e, msg="Failed to describe VPCs")

    def vpc_exists(self, name, cidr_block, multi):
        """Returns None or a vpc object depending on the existence of a VPC. When supplied
        with a CIDR, it will check for matching tags to determine if it is a match
        otherwise it will assume the VPC does not exist and thus return None.
        """
        try:
            matching_vpcs = self.connection.describe_vpcs(Filters=[{'Name': 'tag:Name', 'Values': [name]},
                                                                   {'Name': 'cidr-block', 'Values': cidr_block}])['Vpcs']
            # If an exact matching using a list of CIDRs isn't found, check for a match with the first CIDR as is documented for C(cidr_block)
            if not matching_vpcs:
                matching_vpcs = self.connection.describe_vpcs(Filters=[{'Name': 'tag:Name', 'Values': [name]},
                                                                       {'Name': 'cidr-block', 'Values': [cidr_block[0]]}])['Vpcs']
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.fail_json_aws(e, msg="Failed to describe VPCs")

        if multi:
            return None
        elif len(matching_vpcs) == 1:
            return matching_vpcs[0]
        elif len(matching_vpcs) > 1:
            self.fail_json(msg='Currently there are %d VPCs that have the same name and '
                               'CIDR block you specified. If you would like to create '
                               'the VPC anyway please pass True to the multi_ok param.' % len(matching_vpcs))
        return None

    def update_vpc_tags(self, vpc_id, tags, name):

        if tags is None:
            tags = dict()

        tags.update({'Name': name})
        try:
            current_tags = dict((t['Key'], t['Value'])
                                for t in self.connection.describe_tags(Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}])['Tags'])
            if tags != current_tags:
                tags = ansible_dict_to_boto3_tag_list(tags)
                self.connection.create_tags(Resources=[vpc_id], Tags=tags)
            else:
                return False
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.fail_json_aws(e, msg="Failed to update tags")

    def update_dhcp_opts(self, vpc_obj, dhcp_id):
        if vpc_obj['DhcpOptionsId'] != dhcp_id:
            try:
                self.connection.associate_dhcp_options(DhcpOptionsId=dhcp_id, VpcId=vpc_obj['VpcId'])
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                self.fail_json_aws(e, msg="Failed to associate DhcpOptionsId {0}".format(dhcp_id))
            return True
        else:
            return False


def main():
    argument_spec = dict(
        name=dict(required=True),
        cidr_block=dict(type='list', required=True),
        tenancy=dict(choices=['default', 'dedicated'], default='default'),
        dns_support=dict(type='bool', default=True),
        dns_hostnames=dict(type='bool', default=True),
        dhcp_opts_id=dict(),
        tags=dict(type='dict', aliases=['resource_tags']),
        multi_ok=dict(type='bool', default=False),
        purge_cidrs=dict(type='bool', default=False),
    )

    module = AWSVPCModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )
    if module.params['dns_hostnames'] and not module.params['dns_support']:
        module.fail_json(msg='In order to enable DNS Hostnames you must also enable DNS support')
    module.exit_json(**module.run())


if __name__ == '__main__':
    main()
