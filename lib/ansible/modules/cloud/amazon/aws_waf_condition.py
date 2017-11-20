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

author:
 - Will Thames (@willthames)
 - Mike Mochan (@mmochan)
extends_documentation_fragment: aws
options:
    name:
        description: Name of the Web Application Firewall object to manage
        required: yes
    type:
        description: the type of conditioning to perform
        choices:
        - byte
        - geo
        - ip
        - regex
        - size
        - sql
        - xss
    filters:
        description:
        - A list of the filters against which to condition
        - For C(type)=I(byte), valid keys are C(field_to_match), C(position), C(header), C(transformation)
        - For C(type)=I(geo), the only valid key is C(country)
        - For C(type)=I(ip), the only valid key is C(ip_address)
        - For C(type)=I(regex), valid keys are C(field_to_match), C(transformation) and C(regex_pattern)
        - For C(type)=I(size), valid keys are C(field_to_match), C(transformation), C(comparison) and C(size)
        - For C(type)=I(sql), valid keys are C(field_to_match) and C(transformation)
        - For C(type)=I(xss), valid keys are C(field_to_match) and C(transformation)
        - C(field_to_match) can be one of I(uri), I(query_string), I(header) I(method) and I(body)
        - If C(field_to_match) is I(header), then C(header) must also be specified
        - C(transformation) can be one of I(none), I(compress_white_space), I(html_entity_decode), I(lowercase), I(cmd_line), I(url_decode)
        - C(position), can be one of I(exactly), I(starts_with), I(ends_with), I(contains), I(contains_word),
        - C(comparison) can be one of I(EQ), I(NE), I(LE), I(LT), I(GE), I(GT),
        - C(target_string) is a maximum of 50 bytes
        - C(regex_pattern) is a dict with a C(name) key and C(regex_strings) list of strings to condition
    purge_filters:
        description: Whether to remove existing filters from a condition if not passed in C(filters). Defaults to false
    state:
        description:
        choices:
        - present
        - absent
        default: present

'''

EXAMPLES = '''
  - name: create WAF byte condition
    aws_waf_condition:
      name: my_byte_condition
      filters:
      - field_to_match: header
        position: STARTS_WITH
        target_string: Hello
        header: Content-type
      type: byte

  - name: create WAF geo condition
    aws_waf_condition:
      name: my_geo_condition
      filters:
        - country: US
        - country: AU
        - country: AT
      type: geo

  - name: create IP address condition
    aws_waf_condition:
      name: "{{ resource_prefix }}_ip_condition"
      filters:
        - ip_address: "10.0.0.0/8"
        - ip_address: "192.168.0.0/24"
      type: ip

  - name: create WAF regex condition
    aws_waf_condition:
      name: my_regex_condition
      filters:
        - field_to_match: query_string
          regex_pattern:
            name: greetings
            regex_strings:
              - '[hH]ello'
              - '^Hi there'
              - '.*Good Day to You'
      type: regex

  - name: create WAF size condition
    aws_waf_condition:
      name: my_size_condition
      filters:
        - field_to_match: query_string
          size: 300
          comparison: GT
      type: size

  - name: create WAF sql injection condition
    aws_waf_condition:
      name: my_sql_condition
      filters:
        - field_to_match: query_string
          transformation: url_decode
      type: sql

  - name: create WAF xss condition
    aws_waf_condition:
      name: my_xss_condition
      filters:
        - field_to_match: query_string
          transformation: url_decode
      type: xss

'''

RETURN = '''
condition:
  description: condition returned by operation
  returned: always
  type: complex
  contains:
    condition_id:
      description: type-agnostic ID for the condition
      returned: when state is present
      type: string
      sample: 
    ip_set_descriptors:
      description: list of IP address filters
      returned: when type is ip and state is present
      type: complex
      contains:
        type:
          description: Type of IP address (IPV4 or IPV6)
          returned: always
          type: string
          sample: IPV4
        value:
          description: IP address
          returned: always
          type: string
          sample: 10.0.0.0/8
    ip_set_id:
      description: ID of condition
      returned: when type is ip and state is present
      type: string
      sample: 78ad334a-3535-4036-85e6-8e11e745217b
    name:
      description: Name of condition
      returned: when state is present
      type: string
      sample: my_waf_condition
    regex_match_set_id:
      description: ID of the regex match set
      returned: when type is regex and state is present
      type: string
      sample: 5ea3f6a8-3cd3-488b-b637-17b79ce7089c
    regex_match_tuples:
      description: List of regex matches
      returned: when type is regex and state is present
      type: complex
      contains:
        field_to_match:
          description: Field on which the regex match is applied
          type: complex
          contains:
            type:
              description: The field name
              returned: when type is regex and state is present
              type: string
              sample: QUERY_STRING
        regex_pattern_set_id:
          description: ID of the regex pattern
          type: string
          sample: 6fdf7f2d-9091-445c-aef2-98f3c051ac9e
        text_transformation:
          description: transformation applied to the text before matching
          type: string
          sample: NONE
    size_constraint_set_id:
      description: ID of the size constraint set
      returned: when type is size and state is present
      type: string
      sample: de84b4b3-578b-447e-a9a0-0db35c995656
    size_constraints:
      description: List of size constraints to apply
      returned: when type is size and state is present
      type: complex
      contains:
        comparison_operator:
          description: Comparison operator to apply
          type: string
          sample: GT
        field_to_match:
          description: Field on which the size constraint is applied
          type: complex
          contains:
            type:
              description: Field name
              type: string
              sample: QUERY_STRING
        size:
          description: size to compare against the field
          type: int
          sample: 300
        text_transformation:
          description: transformation applied to the text before matching
          type: string
          sample: NONE
'''

try:
    import botocore
except ImportError:
    pass  # handled by AnsibleAWSModule

from ansible.module_utils.aws.core import AnsibleAWSModule
from ansible.module_utils.ec2 import boto3_conn, get_aws_connection_info, ec2_argument_spec
from ansible.module_utils.ec2 import camel_dict_to_snake_dict, AWSRetry
from ansible.module_utils.aws.waf import get_change_token

MATCH_LOOKUP = {
    'byte': {
        'method': 'byte_match_set',
        'conditionset': 'ByteMatchSet',
        'conditiontuple': 'ByteMatchTuple',
        'type': 'ByteMatch'
    },
    'geo': {
        'method': 'geo_match_set',
        'conditionset': 'GeoMatchSet',
        'conditiontuple': 'GeoMatchConstraint',
        'type': 'GeoMatch'
    },
    'ip': {
        'method': 'ip_set',
        'conditionset': 'IPSet',
        'conditiontuple': 'IPSetDescriptor',
        'type': 'IPMatch'
    },
    'regex': {
        'method': 'regex_match_set',
        'conditionset': 'RegexMatchSet',
        'conditiontuple': 'RegexMatchTuple',
        'type': 'RegexMatch'
    },
    'size': {
        'method': 'size_constraint_set',
        'conditionset': 'SizeConstraintSet',
        'conditiontuple': 'SizeConstraint',
        'type': 'SizeConstraint'
    },
    'sql': {
        'method': 'sql_injection_match_set',
        'conditionset': 'SqlInjectionMatchSet',
        'conditiontuple': 'SqlInjectionMatchTuple',
        'type': 'SQLInjectionMatch',
    },
    'xss': {
        'method': 'xss_match_set',
        'conditionset': 'XssMatchSet',
        'conditiontuple': 'XssMatchTuple',
        'type': 'XssMatch'
    },
}


class Condition(object):

    def __init__(self, client, module):
        self.client = client
        self.module = module
        self.type = module.params['type']
        self.method_suffix = MATCH_LOOKUP[self.type]['method']
        self.conditionset = MATCH_LOOKUP[self.type]['conditionset']
        self.conditionsets = MATCH_LOOKUP[self.type]['conditionset'] + 's'
        self.conditionsetid = MATCH_LOOKUP[self.type]['conditionset'] + 'Id'
        self.conditiontuple = MATCH_LOOKUP[self.type]['conditiontuple']
        self.conditiontuples = MATCH_LOOKUP[self.type]['conditiontuple'] + 's'
        self.conditiontype = MATCH_LOOKUP[self.type]['type']

    def format_for_update(self, condition_set_id):
        # Prep kwargs
        kwargs = dict()
        kwargs['Updates'] = list()

        for filtr in self.module.params.get('filters'):
            # Only for ip_set
            if self.type == 'ip':
                # there might be a better way of detecting an IPv6 address
                if ':' in filtr.get('ip_address'):
                    ip_type = 'IPV6'
                else:
                    ip_type = 'IPV4'
                condition_insert = {'Type': ip_type, 'Value': filtr.get('ip_address')}

            # Specific for geo_match_set
            if self.type == 'geo':
                condition_insert = dict(Type='Country', Value=filtr.get('country'))

            # Common For everything but ip_set and geo_match_set
            if self.type not in ('ip', 'geo'):

                condition_insert = dict(FieldToMatch=dict(Type=filtr.get('field_to_match').upper()),
                                        TextTransformation=filtr.get('transformation', 'none').upper())

                if filtr.get('field_to_match').upper() == "HEADER":
                    if filtr.get('header'):
                        condition_insert['FieldToMatch']['Data'] = filtr.get('header').lower()
                    else:
                        self.module.fail_json(msg=str("DATA required when HEADER requested"))

            # Specific for byte_match_set
            if self.type == 'byte':
                condition_insert['TargetString'] = filtr.get('target_string')
                condition_insert['PositionalConstraint'] = filtr.get('position')

            # Specific for size_constraint_set
            if self.type == 'size':
                condition_insert['ComparisonOperator'] = filtr.get('comparison')
                condition_insert['Size'] = filtr.get('size')

            # Specific for regex_match_set
            if self.type == 'regex':
                condition_insert['RegexPatternSetId'] = self.ensure_regex_pattern_present(filtr.get('regex_pattern'))['RegexPatternSetId']

            kwargs['Updates'].append({'Action': 'INSERT', self.conditiontuple: condition_insert})

        kwargs[self.conditionsetid] = condition_set_id
        kwargs['ChangeToken'] = get_change_token(self.client, self.module)
        return kwargs

    def format_for_deletion(self, condition):
        return {'ChangeToken': get_change_token(self.client, self.module),
                'Updates': [{'Action': 'DELETE', self.conditiontuple: current_condition_tuple}
                            for current_condition_tuple in condition[self.conditiontuples]],
                self.conditionsetid: condition[self.conditionsetid]}

    @AWSRetry.exponential_backoff()
    def list_regex_patterns_with_backoff(self, **params):
        return self.client.list_regex_pattern_sets(**params)

    @AWSRetry.exponential_backoff()
    def get_regex_pattern_set_with_backoff(self, regex_pattern_set_id):
        return self.client.get_regex_pattern_set(RegexPatternSetId=regex_pattern_set_id)

    def list_regex_patterns(self):
        # at time of writing(2017-11-20) no regex pattern paginator exists
        regex_patterns = []
        params = {}
        while True:
            try:
                response = self.list_regex_patterns_with_backoff(**params)
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                self.module.fail_json_aws(e, msg='Could not list regex patterns')
            regex_patterns.extend(response['RegexPatternSets'])
            if 'NextMarker' in response:
                params['NextMarker'] = response['NextMarker']
            else:
                break
        return regex_patterns

    def get_regex_pattern_by_name(self, name):
        existing_regex_patterns = self.list_regex_patterns()
        regex_lookup = dict((item['Name'], item['RegexPatternSetId']) for item in existing_regex_patterns)
        if name in regex_lookup:
            return self.get_regex_pattern_set_with_backoff(regex_lookup[name])['RegexPatternSet']
        else:
            return None

    def ensure_regex_pattern_present(self, regex_pattern):
        name = regex_pattern['name']

        pattern_set = self.get_regex_pattern_by_name(name)
        if not pattern_set:
            pattern_set = self.client.create_regex_pattern_set(Name=name, ChangeToken=get_change_token(self.client, self.module))['RegexPatternSet']
        missing = set(regex_pattern['regex_strings']) - set(pattern_set['RegexPatternStrings'])
        extra = set(pattern_set['RegexPatternStrings']) - set(regex_pattern['regex_strings'])
        if not missing and not extra:
            return pattern_set
        updates = [{'Action': 'INSERT', 'RegexPatternString': pattern} for pattern in missing]
        updates.extend([{'Action': 'DELETE', 'RegexPatternString': pattern} for pattern in extra])
        self.client.update_regex_pattern_set(RegexPatternSetId=pattern_set['RegexPatternSetId'],
                                             Updates=updates, ChangeToken=get_change_token(self.client, self.module))
        return self.get_regex_pattern_set_with_backoff(pattern_set['RegexPatternSetId'])['RegexPatternSet']

    def delete_unused_regex_pattern(self, regex_pattern_set_id):
        try:
            regex_pattern_set = self.client.get_regex_pattern_set(RegexPatternSetId=regex_pattern_set_id)['RegexPatternSet']
            updates = list()
            for regex_pattern_string in regex_pattern_set['RegexPatternStrings']:
                updates.append({'Action': 'DELETE', 'RegexPatternString': regex_pattern_string})
            self.client.update_regex_pattern_set(RegexPatternSetId=regex_pattern_set_id, Updates=updates,
                                                 ChangeToken=get_change_token(self.client, self.module))

            self.client.delete_regex_pattern_set(RegexPatternSetId=regex_pattern_set_id,
                                                 ChangeToken=get_change_token(self.client, self.module))
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.module.fail_json_aws(e, msg='Could not delete regex pattern')

    def get_condition_by_name(self, name):
        all_conditions = [d for d in self.list_conditions() if d['Name'] == name]
        if all_conditions:
            return all_conditions[0][self.conditionsetid]

    @AWSRetry.exponential_backoff()
    def get_condition_by_id_with_backoff(self, condition_set_id):
        params = dict()
        params[self.conditionsetid] = condition_set_id
        func = getattr(self.client, 'get_' + self.method_suffix)
        return func(**params)[self.conditionset]

    def get_condition_by_id(self, condition_set_id):
        try:
            return self.get_condition_by_id_with_backoff(condition_set_id)
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.module.fail_json_aws(e, msg='Could not get condition')

    def list_conditions(self):
        method = 'list_' + self.method_suffix + 's'
        try:
            paginator = self.client.get_paginator(method)
            func = paginator.paginate().build_full_result
        except botocore.exceptions.OperationNotPageableError:
            # list_geo_match_sets and list_regex_match_sets do not have a paginator
            func = getattr(self.client, method)
        try:
            return func()[self.conditionsets]
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.module.fail_json_aws(e, msg='Could not list %s conditions' % self.type)

    def tidy_up_regex_patterns(self, regex_match_set):
        all_regex_match_sets = self.list_conditions()
        all_match_set_patterns = list()
        for rms in all_regex_match_sets:
            all_match_set_patterns.extend(conditiontuple['RegexPatternSetId']
                                              for conditiontuple in self.get_condition_by_id(rms[self.conditionsetid])[self.conditiontuples])
        for filtr in regex_match_set[self.conditiontuples]:
            if filtr['RegexPatternSetId'] not in all_match_set_patterns:
                self.delete_unused_regex_pattern(filtr['RegexPatternSetId'])

    def find_and_delete_condition(self, condition_set_id):
        current_condition = self.get_condition_by_id(condition_set_id)
        if current_condition[self.conditiontuples]:
            # Filters are deleted using update with the DELETE action
            func = getattr(self.client, 'update_' + self.method_suffix)
            params = self.format_for_deletion(current_condition)
            try:
                func(**params)
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                self.module.fail_json_aws(e, msg='Could not delete filters from condition')
        func = getattr(self.client, 'delete_' + self.method_suffix)
        params = dict()
        params[self.conditionsetid] = condition_set_id
        params['ChangeToken'] = get_change_token(self.client, self.module)
        try:
            func(**params)
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            self.module.fail_json_aws(e, msg='Could not delete condition')
        # tidy up regex patterns
        if self.type == 'regex':
            self.tidy_up_regex_patterns(current_condition)
        return True, {}

    def find_and_update_condition(self, condition_set_id):
        current_condition = self.get_condition_by_id(condition_set_id)
        update = self.format_for_update(condition_set_id)
        missing = [desired for desired in update['Updates']
                   if desired[self.conditiontuple] not in current_condition[self.conditiontuples]]
        if self.module.params.get('purge_filters'):
            extra = [{'Action': 'DELETE', self.conditiontuple: current_tuple}
                     for current_tuple in current_condition[self.conditiontuples]
                     if current_tuple not in [desired[self.conditiontuple] for desired in update['Updates']]]
        else:
            extra = []
        changed = bool(missing or extra)
        if changed:
            update['Updates'] = missing + extra
            func = getattr(self.client, 'update_' + self.method_suffix)
            try:
                func(**update)
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                self.module.fail_json_aws(e, msg='Could not update condition')
        return changed, self.get_condition_by_id(condition_set_id)

    def ensure_condition_present(self):
        name = self.module.params['name']
        condition_set_id = self.get_condition_by_name(name)
        if condition_set_id:
            return self.find_and_update_condition(condition_set_id)
        else:
            params = dict()
            params['Name'] = name
            params['ChangeToken'] = get_change_token(self.client, self.module)
            func = getattr(self.client, 'create_' + self.method_suffix)
            try:
                condition = func(**params)
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                self.module.fail_json_aws(e, msg='Could not create condition')
            return self.find_and_update_condition(condition[self.conditionset][self.conditionsetid])

    def ensure_condition_absent(self):
        condition_set_id = self.get_condition_by_name(self.module.params['name'])
        if condition_set_id:
            return self.find_and_delete_condition(condition_set_id)
        return False, {}


def main():
    filters_subspec = dict(
        country=dict(),
        field_to_match=dict(choices=['uri', 'query_string', 'header', 'method', 'body']),
        header=dict(),
        transformation=dict(choices=['none', 'compress_white_space',
                                     'html_entity_decode', 'lowercase',
                                     'cmd_line', 'url_decode']),
        position=dict(choices=['exactly', 'starts_with', 'ends_with',
                               'contains', 'contains_word']),
        comparison=dict(choices=['EQ', 'NE', 'LE', 'LT', 'GE', 'GT']),
        target_string=dict(),  # Bytes
        size=dict(type='int'),
        ip_address=dict(),
        regex_pattern=dict(),
    )
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True),
            type=dict(required=True, choices=['byte', 'geo', 'ip', 'regex', 'size', 'sql', 'xss']),
            filters=dict(type='list'),
            purge_filters=dict(type='bool', default=False),
            state=dict(default='present', choices=['present', 'absent']),
        ),
    )
    module = AnsibleAWSModule(argument_spec=argument_spec,
                              required_if=[['state', 'present', ['filters']]])
    state = module.params.get('state')

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
    client = boto3_conn(module, conn_type='client', resource='waf', region=region, endpoint=ec2_url, **aws_connect_kwargs)

    condition = Condition(client, module)

    if state == 'present':
        (changed, results) = condition.ensure_condition_present()
        # return a condition agnostic ID for use by aws_waf_rule
        results['ConditionId'] = results[condition.conditionsetid]
    else:
        (changed, results) = condition.ensure_condition_absent()

    module.exit_json(changed=changed, condition=camel_dict_to_snake_dict(results))


if __name__ == '__main__':
    main()
