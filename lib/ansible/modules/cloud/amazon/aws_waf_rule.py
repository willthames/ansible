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
module: aws_waf_rule
short_description: create and delete WAF ACLs, Rules, Conditions, and Filters.
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
        description: Name of the Web Application Firewall rule
        required: yes
    metric_name:
        description:
        - A friendly name or description for the metrics for the rule
        - The name can contain only alphanumeric characters (A-Z, a-z, 0-9); the name can't contain whitespace.
        - You can't change metric_name after you create the rule
    state:
        description: whether the rule should be present or absent
        choices:
        - present
        - absent
        default: present
    predicates:
        description: list of predicates used in the rule. Each predicate should
          contain C(type): one of [I(byte), I(geo), I(ip), I(size), I(sql) or I(xss)]
          C(negated): whether the predicate should be negated, and C(match),
          the name of the existing match. M(aws_waf_match) can be used to
          create new matches

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
from ansible.module_utils.ec2 import camel_dict_to_snake_dict, AWSRetry
from ansible.module_utils.aws.waf import get_change_token, list_rules_with_backoff


predicate_types = {
    'byte': 'ByteMatch',
    'geo': 'GeoMatch',
    'ip': 'IPMatch',
    'sql': 'SqlInjectionMatch',
    'size': 'SizeConstraint',
    'xss': 'XssMatch'
}

list_methods = {
    'byte': 'list_byte_match_sets',
    'geo': 'list_geo_match_sets',
    'ip': 'list_ip_sets',
    'sql': 'list_sql_injection_match_sets',
    'size': 'list_size_constraint_sets',
    'xss': 'list_xss_match_sets'
}


@AWSRetry.exponential_backoff
def update_rule_with_backoff(client, **kwargs):
    return client.update_rule(**kwargs)


def get_rule_by_name(client, module, name):
    rules = [d['RuleId'] for d in list_rules(client, module) if d['Name'] == name]
    if rules:
        return rules[0]


def get_rule(client, module, rule_id):
    try:
        return client.get_rule(RuleId=rule_id)['Rule']
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg='Could not get WAF rule')


def list_rules(client, module):
    try:
        return list_rules_with_backoff(client, module.client)['Rules']
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg='Could not list WAF rules')


def find_and_update_rule(client, module, rule_id):
    rule = get_rule(client, module, rule_id)
    rule_id = rule['RuleId']

    for predicate_type in list_methods:
        existing_predicates = dict(predicate_type={})
        desired_predicates = dict(predicate_type={})
        all_predicates = dict(predicate_type={})

    for predicate in rule['Predicates']:
        existing_predicates[predicate['Type']][predicate['Name']] = camel_dict_to_snake_dict(predicate)
    for predicate in module.params['predicates']:
        paginator = client.get_paginator(list_methods[predicate['type']])
        try:
            pred_results = paginator.paginate().build_full_result()[predicate_types[predicate['type']] + 'Set']
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            module.fail_json_aws(e, msg='Could not list %s match sets' % predicate['type'])
        all_predicates[predicate['type']] = dict((pred['Name'], camel_dict_to_snake_dict(pred)) for pred in pred_results)
        desired_predicates[predicate['type']][predicate['name']] = predicate

    for predicate in desired_predicates:
        if not predicate['name'] in all_predicates[predicate['type']]:
            module.fail_json(msg="Predicate %s of type %s does not exist" % (predicate['name'], predicate['type']))
        if not predicate['name'] in existing_predicates[predicate['type']]:
            predicate['data_id'] = all_predicates[predicate['type']][predicate['name']]['data_id']
            changed = True
            insert_rule_predicate(client, module, rule_id, predicate)

    if module.params['purge_predicates']:
        for predicate in existing_predicates:
            if not predicate['name'] in desired_predicates[predicate['type']]:
                changed = True
                remove_rule_predicate(client, module, rule_id, predicate)

    return changed, get_rule(client, module, rule_id)


def insert_rule_predicate(client, module, rule_id, predicate):
    try:
        return update_rule_with_backoff(
            client,
            module,
            RuleId=rule_id,
            ChangeToken=get_change_token(client, module),
            Updates=[
                {'Action': 'INSERT',
                    'Predicate': {
                        'Negated': predicate['negated'],
                        'Type': predicate['type'],
                        'DataId': predicate['data_id']
                    }
                 }
            ]
        )
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg='Could not add rule predicate')


def remove_rule_predicates(client, module, rule_id):
    predicates = get_rule(client, module, rule_id)['Predicates']
    for predicate in predicates:
        remove_rule_predicate(client, module, rule_id, predicate)
    return True, ""


def remove_rule_predicate(client, module, rule_id, predicate):
    try:
        update_rule_with_backoff(
            client,
            module,
            RuleId=rule_id,
            ChangeToken=get_change_token(client, module),
            Updates=[
                {
                    'Action': 'DELETE',
                    'Predicate': {
                        'Negated': predicate['Negated'],
                        'Type': predicate['Type'],
                        'DataId': predicate['DataId']
                    }
                }
            ]
        )
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg='Could not remove rule predicate')


def create_rule(client, module):
    name = module.params['name']
    rule_id = get_rule_by_name(client, module, name)
    params = dict()
    if rule_id:
        return find_and_update_rule(client, module, rule_id)
    else:
        params['Name'] = module.params['name']
        params['MetricName'] = module.params['metric_name']
        params['ChangeToken'] = get_change_token(client, module)
        try:
            new_rule = client.create_rule(**params)['Rule']
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            module.fail_json_aws(e, msg='Could not create rule')
        return find_and_update_rule(new_rule['RuleId'])


def delete_rule(client, module):
    rule_id = get_rule_by_name(client, module, module.params['name'])
    if rule_id:
        remove_rule_predicates(client, module, rule_id)
        try:
            return True, client.delete_rule(RuleId=rule_id, ChangeToken=get_change_token(client, module.client))
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            module.fail_json_aws(e, msg='Could not delete rule')
    return False, None


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True),
            state=dict(default='present', choices=['present', 'absent']),
            predicate=dict(type='list'),
        ),
    )
    module = AnsibleAWSModule(argument_spec=argument_spec)
    state = module.params.get('state')

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
    client = boto3_conn(module, conn_type='client', resource='waf', region=region, endpoint=ec2_url, **aws_connect_kwargs)

    if state == 'present':
        (changed, results) = create_rule(client, module)
    else:
        (changed, results) = delete_rule(client, module)

    module.exit_json(changed=changed, waf=results)


if __name__ == '__main__':
    main()
