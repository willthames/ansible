#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
DOCUMENTATION = '''
module: aws_waf_web_acl
short_description: create and delete WAF Web ACLs
description:
  - Read the AWS documentation for WAF
    U(https://aws.amazon.com/documentation/waf/)
version_added: "2.5"

author:
- Mike Mochan (@mmochan)
- Will Thames (@willthames)
extends_documentation_fragment: aws
options:
    name:
        description: Name of the Web Application Firewall object to manage
        required: yes
    default_action:
        description: The action that you want AWS WAF to take when a request doesn't
          match the criteria specified in any of the Rule objects that are associated with the WebACL
        choices:
        - block
        - allow
        - count
    state:
        description: whether the Web ACL should be present or absent
        choices:
        - present
        - absent
        default: present
    metric_name:
        description:
        - A friendly name or description for the metrics for this WebACL
        - The name can contain only alphanumeric characters (A-Z, a-z, 0-9); the name can't contain whitespace.
        - You can't change metric_name after you create the WebACL
    rules:
        description: A list of rules that the Web ACL will enforce
'''

EXAMPLES = '''


'''
RETURN = '''
task:
  description: The result of the create, or delete action.
  returned: success
  type: dictionary
'''

try:
    import botocore
except ImportError:
    pass  # handled by AnsibleAWSModule

from ansible.module_utils.aws.core import AnsibleAWSModule
from ansible.module_utils.ec2 import boto3_conn, get_aws_connection_info, ec2_argument_spec
from ansible.module_utils.aws.waf import list_rules_with_backoff, list_web_acls_with_backoff, get_change_token


def get_web_acl_by_name(client, module, name):
    acls = [d['WebACLId'] for d in list_web_acls(client, module) if d['Name'] == name]
    if acls:
        return acls[0]
    else:
        return acls


def get_rule_by_name(client, module, name):
    try:
        rules = list_rules_with_backoff(client)['Rules']
        rule_id = [d['RuleId'] for d in rules if d['Name'] == name][0]
        return client.get_rule(RuleId=rule_id)['Rule']
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg='')


def get_web_acl(client, module, web_acl_id):
    try:
        return client.get_web_acl(WebACLId=web_acl_id)['WebACL']
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg='Could not get Web ACL with id %s' % web_acl_id)


def list_web_acls(client, module,):
    try:
        return list_web_acls_with_backoff(client)['WebACLs']
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg='Could not get Web ACLs')


def find_and_update_web_acl(client, module, web_acl_id):
    changed = False
    acl = get_web_acl(client, module, web_acl_id)
    result = list()
    for rule in module.params['rules']:
        existing_rule = get_rule_by_name(client, module, rule['name'])
        update_web_acl(client, module, rule, acl, existing_rule)
    changed = True
    return changed, result


def update_web_acl(client, module, new_rule_config, acl, existing_rule):
    try:
        return client.update_web_acl(
            WebACLId=acl['WebACLId'],
            ChangeToken=get_change_token(client, module),
            Updates=[
                {
                    'Action': 'INSERT',
                    'ActivatedRule': {
                        'Priority': new_rule_config['rule_priority'],
                        'RuleId': existing_rule['RuleId'],
                        'Action': {
                            'Type': new_rule_config['rule_action'].upper()
                        }
                    }
                },
            ],
            DefaultAction={
                'Type': module.params['default_action']
            }
        )
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg='Could not update Web ACL')


def remove_rule_from_web_acl(client, module, rule, acl):
    try:
        return client.update_web_acl(
            WebACLId=acl['WebACLId'],
            ChangeToken=get_change_token(client, module),
            Updates=[
                {
                    'Action': "DELETE",
                    'ActivatedRule': {
                        'Priority': rule['Priority'],
                        'RuleId': rule['RuleId'],
                        'Action': {
                            'Type': rule['Action']['Type']
                        }
                    }
                },
            ],
            DefaultAction={
                'Type': module.params['default_action']
            }
        )
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg='Could not remove rule')


def remove_rules_from_web_acl(client, module, web_acl_id):
    changed = False
    result = None
    acl = get_web_acl(module, client, web_acl_id)
    for rule in acl['Rules']:
        remove_rule_from_web_acl(client, module, rule, acl)
        changed = True
    return changed, result


def create_web_acl(client, module):
    changed = False
    result = None
    name = module.params['name']
    web_acl_id = get_web_acl_by_name(client, module, name)
    if web_acl_id:
        (changed, result) = find_and_update_web_acl(client, module, web_acl_id)
    else:
        metric_name = module.params['metric_name']
        default_action = module.params['default_action']
        try:
            new_web_acl = client.create_web_acl(Name=name, MetricName=metric_name,
                                                DefaultAction={'Type': default_action},
                                                ChangeToken=get_change_token(client, module))
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            module.fail_json_aws(e, msg='Could not create Web ACL')
        (changed, result) = find_and_update_web_acl(client, module, new_web_acl['WebACL']['WebACLId'])
    return changed, result


def delete_web_acl(client, module):
    web_acl_id = get_web_acl_by_name(client, module, module.params['name'])
    if web_acl_id:
        remove_rules_from_web_acl(client, module, web_acl_id)
        try:
            return True, client.delete_web_acl(WebACLId=web_acl_id, ChangeToken=get_change_token(client, module))
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            module.fail_json_aws(e, msg='Could not delete Web ACL')
    return False, None


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True),
            default_action=dict(choices=['block', 'allow', 'count']),
            metric_name=dict(),
            state=dict(default='present', choices=['present', 'absent']),
            rules=dict(type='list')
        ),
    )
    module = AnsibleAWSModule(argument_spec=argument_spec,
                              required_if=[['state', 'present', ['metric_name', 'default_action', 'rules']]])
    state = module.params.get('state')

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
    client = boto3_conn(module, conn_type='client', resource='waf', region=region, endpoint=ec2_url, **aws_connect_kwargs)

    if state == 'present':
        (changed, results) = create_web_acl(client, module)
    else:
        (changed, results) = delete_web_acl(client, module)

    module.exit_json(changed=changed, waf=results)


if __name__ == '__main__':
    main()
