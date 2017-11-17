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
module: aws_waf
short_description: create and delete WAF ACLs, Rules, Conditions, and Filters.
description:
  - Read the AWS documentation for WAF
    U(https://aws.amazon.com/documentation/waf/)
version_added: "2.5"

author: Mike Mochan(@mmochan)
extends_documentation_fragment: aws
options:
    name:
        description: Name of the Web Application Firewall object to manage
        required: yes
    waf_type:
        description: Type of Web Application Firewall object to manage
        required: yes
        choices:
        - web_acl
        - rule
        - condition
    type:
        description:
        choices:
        - xss
        - byte
        - size
        - sql
        - ip
    field_match:
        description:
        choices:
        - uri
        - query_string
        - header
        - method
        - body
    header_data:
        description:
        choices:
        - Accept
        - Accept-Encoding
        - Accept-Language
        - Authorization
        - Cache-Control
        - Connection
        - Content-Length
        - Content-Type
        - Cookie
        - Expect
        - From
        - Host
        - Origin
        - Proxy-Authorization
        - Referer
        - Upgrade
        - User-Agent
        - Via
    transformation:
        description:
        choices:
        - none
        - compress_white_space
        - html_entity_decode
        - lowercase
        - cmd_line
        - url_decode
    default_action:
        description:
        choices:
        - block
        - allow
        - count
    positional:
        description:
        choices:
        - exactly
        - starts_with
        - ends_with
        - contains
        - contains_word
    comparison:
        description:
        choices:
        - EQ
        - NE
        - LE
        - LT
        - GE
        - GT
    state:
        description:
        choices:
        - present
        - absent
        default: present
    metric_name:
        description:
    target_string:
        description:
    size:
        description:
    ip_address:
        description:
    negated:
        description:
    conditions:
        description:
    rules:
        description:

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
from ansible.module_utils.ec2 import boto3_conn, get_aws_connection_info, ec2_argument_spec, AWSRetry


conditions = {
    'xss': {'method': 'xss_match_set', 'matchsets': 'XssMatchSets',
            'matchset': 'XssMatchSet', 'matchsetid': 'XssMatchSetId',
            'matchtuple': 'XssMatchTuple', 'matchtuples': 'XssMatchTuples'},
    'ip': {'method': 'ip_set', 'matchsets': 'IPSets',
           'matchset': 'IPSet', 'matchsetid': 'IPSetId',
           'matchtuple': 'IPSetDescriptor', 'matchtuples': 'IPSetDescriptors'},
    'byte': {'method': 'byte_match_set', 'matchsets': 'ByteMatchSets',
             'matchset': 'ByteMatchSet', 'matchsetid': 'ByteMatchSetId',
             'matchtuple': 'ByteMatchTuple', 'matchtuples': 'ByteMatchTuples'},
    'size': {'method': 'size_constraint_set', 'matchsets': 'SizeConstraintSets',
             'matchset': 'SizeConstraintSet', 'matchsetid': 'SizeConstraintSetId',
             'matchtuple': 'SizeConstraint', 'matchtuples': 'SizeConstraints'},
    'sql': {'method': 'sql_injection_match_set', 'matchsets': 'SqlInjectionMatchSets',
            'matchset': 'SqlInjectionMatchSet', 'matchsetid': 'SqlInjectionMatchSetId',
            'matchtuple': 'SqlInjectionMatchTuple', 'matchtuples': 'SqlInjectionMatchTuples'}
}


@AWSRetry.exponential_backoff()
def list_rules_with_backoff(client):
    paginator = client.get_paginator('list_rules')
    return paginator.paginate().build_full_result()


@AWSRetry.exponential_backoff()
def list_web_acls_with_backoff(client):
    paginator = client.get_paginator('list_web_acls')
    return paginator.paginate().build_full_result()


class Condition():
    def __init__(self, options, client, module):
        self.matchsets = options['matchsets']
        self.matchset = options['matchset']
        self.matchsetid = options['matchsetid']
        self.matchtuple = options['matchtuple']
        self.matchtuples = options['matchtuples']
        self.method_suffix = options['method']

        self.client = client
        self.module = module
        self.name = module.params.get('name')
        self.action = module.params.get('action').upper()

        # Prep kwargs
        self.kwargs = dict()
        self.kwargs['Updates'] = list()

        # Only for ip_set
        if self.method_suffix == 'ip_set':
            self.kwargs['Updates'].append({'Action': self.action, self.matchtuple: {}})
            self.kwargs['Updates'][0][self.matchtuple]['Type'] = 'IPV4'
            self.kwargs['Updates'][0][self.matchtuple]['Value'] = module.params.get('ip_address')

        # Common For everything but  IP_SET
        if self.method_suffix != 'ip_set':
            self.kwargs['Updates'].append({'Action': self.action, self.matchtuple: {'FieldToMatch': {}}})
            self.kwargs['Updates'][0][self.matchtuple]['FieldToMatch']['Type'] = module.params.get('field_match').upper()
            self.kwargs['Updates'][0][self.matchtuple]['TextTransformation'] = module.params.get('transformation').upper()

        # Whenever HEADER is set but not for ip_set
        if self.method_suffix != 'ip_set':
            if module.params.get('field_match').upper() == "HEADER":
                if module.params.get('header_data').lower():
                    self.kwargs['Updates'][0][self.matchtuple]['FieldToMatch']['Data'] = module.params.get('header_data').lower()
                else:
                    self.module.fail_json(msg=str("DATA required when HEADER requested"))

        # Specific for byte_match_set
        if self.method_suffix == 'byte_match_set':
            self.kwargs['Updates'][0][self.matchtuple]['TargetString'] = module.params.get('target_string')
            self.kwargs['Updates'][0][self.matchtuple]['PositionalConstraint'] = module.params.get('positional').upper()

        # Specific for size_constraint_set
        if self.method_suffix == 'size_constraint_set':
            self.kwargs['Updates'][0][self.matchtuple]['ComparisonOperator'] = module.params.get('comparison')
            self.kwargs['Updates'][0][self.matchtuple]['Size'] = module.params.get('size')

    def format_for_update(self, match_set_id):
        self.kwargs[self.matchsetid] = match_set_id
        self.kwargs['ChangeToken'] = get_change_token(self.client, self.module)
        return self.kwargs

    def format_for_deletion(self, match_set_id, filters):
        result = []
        for filter in filters:
            formatted_filters = {'ChangeToken': get_change_token(self.client, self.module),
                                 'Updates': [{'Action': 'DELETE', self.matchtuple: filter}],
                                 self.matchsetid: match_set_id
                                 }
            result.append(formatted_filters)
        return result

    def exists(self):
        return any(d['Name'] == self.name for d in self.list())

    def create(self):
        params = dict()
        params['Name'] = self.module.params.get('name')
        params['ChangeToken'] = get_change_token(self.client, self.module)
        func = getattr(self.client, 'create_' + self.method_suffix)
        try:
            return func(**params)
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.module.fail_json_aws(e, msg='')

    def delete(self, match_set_id):
        params = dict()
        params[self.matchsetid] = match_set_id
        params['ChangeToken'] = get_change_token(self.client, self.module)
        func = getattr(self.client, 'delete_' + self.method_suffix)
        return func(**params)

    def get(self, match_set_id):
        params = dict()
        params[self.matchsetid] = match_set_id
        func = getattr(self.client, 'get_' + self.method_suffix)
        return func(**params)[self.matchset]

    def list(self):
        paginator = self.client.get_paginator('list_' + self.method_suffix + 's')
        return paginator.paginate().build_full_result()[self.matchsets]

    def find_and_delete(self):
        match_set_id = [c[self.matchsetid] for c in self.list() if c['Name'] == self.name][0]
        current_filters = self.get(match_set_id)[self.matchtuples]
        result = []
        for filter in self.format_for_deletion(match_set_id, current_filters):
            result.append(self.delete_filter(filter))
        response = self.get(match_set_id)
        self.delete(match_set_id)
        return True, response

    def delete_filter(self, filter):
        # Filters are deleted using update with the DELETE action
        func = getattr(self.client, 'update_' + self.method_suffix)
        try:
            return func(**filter)
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.module.fail_json_aws(e, msg='Could not delete filter')

    def find_and_update_filter(self):
        match_set_id = [c[self.matchsetid] for c in self.list() if c['Name'] == self.name][0]
        current_filters = self.get(match_set_id)[self.matchtuples]
        if self.has_matching_filter(current_filters, self.format_for_update(match_set_id)):
            if self.action == 'DELETE':
                response = self.get(match_set_id)
                self.update(match_set_id)
                return True, response
            return False, self.get(match_set_id)
        else:
            if self.action == 'INSERT':
                response = self.update(match_set_id)
                return True, self.get(match_set_id)
            # return False, "Filter update not required"
            return False, self.get(match_set_id)

    def has_matching_filter(self, current_filters, new_filters):
        return [f for f in current_filters if f == new_filters['Updates'][0][self.matchtuple]]

    def update(self, id):
        func = getattr(self.client, 'update_' + self.method_suffix)
        try:
            return func(**self.format_for_update(id))
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.module.fail_json_aws(e, msg='Could not update')


class Rule:
    # def __str__(self):
    #     return str(self.__dict__)

    def __init__(self, client, module):
        self.client = client
        self.module = module
        self.changed = False

        self.condition_types = {
            'ip': 'IPMatch', 'byte': 'ByteMatch',
            'sql': 'SqlInjectionMatch',
            'size': 'SizeConstraint', 'xss': 'XssMatch'
        }
        self.list_methods = {
            'ip': 'list_ip_sets', 'byte': 'list_byte_match_sets',
            'sql': 'list_sql_injection_match_sets',
            'size': 'list_size_constraint_sets', 'xss': 'list_xss_match_sets'}

        self.conditions = module.params.get('conditions')
        self.name = module.params.get('name')
        self.action = module.params.get('action').upper()
        self.metric_name = module.params.get('metric_name')
        self.negated = module.params.get('negated')

    def exists(self):
        rules = [d['RuleId'] for d in self.list() if d['Name'] == self.name]
        if rules:
            return rules[0]

    def create(self):
        params = dict()
        params['Name'] = self.name
        params['MetricName'] = self.metric_name
        params['ChangeToken'] = get_change_token(self.client)
        return self.client.create_rule(**params)['Rule']

    def delete(self, rule_id):
        return self.client.delete_rule(RuleId=rule_id, ChangeToken=get_change_token(self.client))

    def get(self, rule_id):
        return self.client.get_rule(RuleId=rule_id)['Rule']

    def list(self):
        return list_rules_with_backoff(self.client)['Rules']

    def find_and_update(self, id):
        rule_id = self.get(id)['RuleId']
        predicates = self.get(id)['Predicates']
        for condition in self.conditions:
            func = self.client.get_paginator(self.list_methods[condition['type']])
            list_results = paginator.paginate().build_full_result()
            key_list = [list_results[key] for key in list_results if key.endswith('Sets')][0]
            this_condition = [k for k in key_list if k['Name'] == condition['name']][0]
            condition_id = [this_condition[key] for key in this_condition if key.endswith('SetId')][0]
            if len(predicates) == 0 or self.action == "DELETE":
                self.update(rule_id, condition_id, condition['type'])
                self.changed = True
        return self.changed, self.get(id)

    def get_condition(self, name):
        params = dict()
        params[self.matchsetid] = id
        func = getattr(self.client, 'get_' + self.method_suffix)
        return func(**params)[self.matchset]

    def update(self, role_id, condition_id, condition_type):
        return self.client.update_rule(
            RuleId=role_id,
            ChangeToken=get_change_token(self.client, self.module),
            Updates=[
                {'Action': self.action,
                    'Predicate': {
                        'Negated': self.negated,
                        'Type': self.condition_types[condition_type],
                        'DataId': condition_id
                    }
                 }
            ]
        )

    def remove_rule_conditions(self, rule_id):
        predicates = self.get(rule_id)['Predicates']
        for predicate in predicates:
            condition = {"Action": "DELETE", "Predicate": predicate}
            self.client.update_rule(
                RuleId=rule_id,
                ChangeToken=get_change_token(self.client, self.module),
                Updates=[
                    {
                        'Action': condition['Action'],
                        'Predicate': {
                            'Negated': condition['Predicate']['Negated'],
                            'Type': condition['Predicate']['Type'],
                            'DataId': condition['Predicate']['DataId']
                        }
                    }
                ]
            )
        return True, ""


class WebAcl():

    def __init__(self, client, module):
        self.client = client
        self.module = module
        self.name = module.params.get('name')
        self.metric_name = module.params.get('metric_name')
        self.default_action = module.params.get('default_action').upper()
        self.action = module.params.get('action').upper()
        self.rules = module.params.get('rules')

    def exists(self):
        acls = [d['WebACLId'] for d in self.list() if d['Name'] == self.name]
        if acls:
            return acls[0]
        else:
            return acls

    def get_rule_by_name(self, name):
        try:
            rules = list_rules_with_backoff(self.client)['Rules']
            rule_id = [d['RuleId'] for d in rules if d['Name'] == name][0]
            return self.client.get_rule(RuleId=rule_id)['Rule']
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.module.fail_json_aws(e, msg='')

    def create(self):
        try:
            return self.client.create_web_acl(
                Name=self.name,
                MetricName=self.metric_name,
                DefaultAction={
                    'Type': self.default_action
                },
                ChangeToken=get_change_token(self.client, self.module)
            )
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.module.fail_json_aws(e, msg='Could not create Web ACL')

    def delete(self, web_acl_id):
        try:
            return True, self.client.delete_web_acl(WebACLId=web_acl_id, ChangeToken=get_change_token(self.client, self.module))
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.module.fail_json_aws(e, msg='Could not delete Web ACL')

    def get(self, web_acl_id):
        try:
            return self.client.get_web_acl(WebACLId=web_acl_id)['WebACL']
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.module.fail_json_aws(e, msg='Could not get Web ACL with id %s' % web_acl_id)

    def list(self):
        try:
            return list_web_acls_with_backoff(self.client)['WebACLs']
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.module.fail_json_aws(e, msg='Could not get Web ACLs')

    def find_and_update(self, web_acl_id):
        changed = False
        acl = self.get(web_acl_id)
        result = list()
        for rule in self.rules:
            existing_rule = self.get_rule_by_name(rule['name'])
            self.update(rule, acl, existing_rule)
        changed = True
        return changed, result

    def update(self, new_rule_config, acl, existing_rule):
        try:
            return self.client.update_web_acl(
                WebACLId=acl['WebACLId'],
                ChangeToken=get_change_token(self.client, self.module),
                Updates=[
                    {
                        'Action': self.action,
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
                    'Type': self.default_action
                }
            )
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.module.fail_json_aws(e, msg='Could not update Web ACL')

    def remove_rule(self, rule, acl):
        try:
            return self.client.update_web_acl(
                WebACLId=acl['WebACLId'],
                ChangeToken=get_change_token(self.client, self.module),
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
                    'Type': self.default_action
                }
            )
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.module.fail_json_aws(e, msg='Could not remove rule')

    def remove_rules(self, web_acl_id):
        changed = False
        result = None
        acl = self.get(web_acl_id)
        for rule in acl['Rules']:
            self.remove_rule(rule, acl)
            changed = True
        return changed, result


def create_web_acl(client, module):
    changed = False
    result = None
    web_acl = WebAcl(client, module)
    web_acl_id = web_acl.exists()
    if web_acl_id:
        (changed, result) = web_acl.find_and_update(web_acl_id)
    else:
        new_web_acl = web_acl.create()
        (changed, result) = web_acl.find_and_update(new_web_acl['WebACL']['WebACLId'])
    return changed, result


def delete_web_acl(client, module):
    changed = False
    result = None
    web_acl = WebAcl(client, module)
    web_acl_id = web_acl.exists()
    if web_acl_id:
        web_acl.remove_rules(web_acl_id)
        (changed, result) = web_acl.delete(web_acl_id)
    return changed, result


def create_rule(client, module):
    changed = False
    result = None
    rule = Rule(client, module)
    rule_id = rule.exists()
    if rule_id:
        (changed, result) = rule.find_and_update(rule_id)
    else:
        new_rule = rule.create()
        (changed, result) = rule.find_and_update(new_rule['RuleId'])
    return changed, result


def delete_rule(client, module):
    changed = False
    result = None
    rule = Rule(client, module)
    rule_id = rule.exists()
    if rule_id:
        rule.remove_rule_conditions(rule_id)
        (changed, result) = rule.delete(rule_id)
    return changed, result


def create_condition(client, module):
    changed = False
    result = None
    condition = Condition(conditions[module.params.get('type')], client, module)
    if condition.exists():
        (changed, result) = condition.find_and_update_filter()
        return changed, result
    else:
        condition.create()
        (changed, result) = condition.find_and_update_filter()
        return changed, "result"


def delete_condition(client, module):
    changed = False
    result = None
    condition = Condition(conditions[module.params.get('type')], client, module)
    if condition.exists():
        (changed, result) = condition.find_and_delete()
    return changed, result


# Token method

def get_change_token(client, module):
    try:
        token = client.get_change_token()
        return token['ChangeToken']
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg='')


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True),
            waf_type=dict(required=True, choices=['web_acl', 'rule', 'condition']),
            type=dict(choices=['xss', 'byte', 'size', 'sql', 'ip']),
            field_match=dict(choices=['uri', 'query_string', 'header', 'method', 'body']),
            header_data=dict(choices=['Accept', 'Accept-Encoding',
                                      'Accept-Language', 'Authorization',
                                      'Cache-Control', 'Connection',
                                      'Content-Length', 'Content-Type',
                                      'Cookie', 'Expect', 'From', 'Host',
                                      'Origin', 'Proxy-Authorization',
                                      'Referer', 'Upgrade', 'User-Agent', 'Via']),
            transformation=dict(choices=['none', 'compress_white_space',
                                         'html_entity_decode', 'lowercase',
                                         'cmd_line', 'url_decode']),
            default_action=dict(choices=['block', 'allow', 'count']),
            positional=dict(choices=['exactly', 'starts_with', 'ends_with',
                                     'contains', 'contains_word']),
            comparison=dict(choices=['EQ', 'NE', 'LE', 'LT', 'GE', 'GT']),
            metric_name=dict(),
            state=dict(default='present', choices=['present', 'absent']),
            target_string=dict(),  # Bytes
            size=dict(type='int'),
            ip_address=dict(),
            negated=dict(type='bool'),
            conditions=dict(type='list'),
            rules=dict(type='list')
        ),
    )
    module = AnsibleAWSModule(argument_spec=argument_spec)
    state = module.params.get('state')

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
    client = boto3_conn(module, conn_type='client', resource='waf', region=region, endpoint=ec2_url, **aws_connect_kwargs)

    if module.params.get('waf_type') == 'web_acl':
        invocations = {
            "present": create_web_acl,
            "absent": delete_web_acl
        }

    if module.params.get('waf_type') == 'condition':
        invocations = {
            "present": create_condition,
            "absent": delete_condition
        }

    if module.params.get('waf_type') == 'rule':
        invocations = {
            "present": create_rule,
            "absent": delete_rule
        }
    (changed, results) = invocations[state](client, module)
    module.exit_json(changed=changed, waf=results)


if __name__ == '__main__':
    main()
