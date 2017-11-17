#!/usr/bin/python
# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from ansible.module_utils.ec2 import camel_dict_to_snake_dict, AWSRetry


try:
    import botocore
except ImportError:
    pass  # caught by imported HAS_BOTO3


@AWSRetry.backoff(tries=5, delay=5, backoff=2.0)
def get_rule_with_backoff(client, rule_id):
    return client.get_rule(RuleId=rule_id)


@AWSRetry.backoff(tries=5, delay=5, backoff=2.0)
def get_byte_match_set_with_backoff(client, byte_match_set_id):
    return client.get_byte_match_set(ByteMatchSetId=byte_match_set_id)['ByteMatchSet']


@AWSRetry.backoff(tries=5, delay=5, backoff=2.0)
def get_ip_set_with_backoff(client, ip_set_id):
    return client.get_ip_set(IPSetId=ip_set_id)['IPSet']


@AWSRetry.backoff(tries=5, delay=5, backoff=2.0)
def get_size_constraint_set_with_backoff(client, size_constraint_set_id):
    return client.get_size_constraint_set(SizeConstraintSetId=size_constraint_set_id)['SizeConstraintSet']


@AWSRetry.backoff(tries=5, delay=5, backoff=2.0)
def get_sql_injection_match_set_with_backoff(client, sql_injection_match_set_id):
    return client.get_sql_injection_match_set(SqlInjectionMatchSetId=sql_injection_match_set_id)['SqlInjectionMatchSet']


@AWSRetry.backoff(tries=5, delay=5, backoff=2.0)
def get_xss_match_set_with_backoff(client, xss_match_set_id):
    return client.get_xss_match_set(XssMatchSetId=xss_match_set_id)['XssMatchSet']


def get_rule(client, module, rule_id):
    try:
        rule = get_rule_with_backoff(client, rule_id)['Rule']
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg="Couldn't obtain waf rule")

    match_sets = {
        'ByteMatch': get_byte_match_set_with_backoff,
        'IPMatch': get_ip_set_with_backoff,
        'SizeConstraint': get_size_constraint_set_with_backoff,
        'SqlInjectionMatch': get_sql_injection_match_set_with_backoff,
        'XssMatch': get_xss_match_set_with_backoff
    }
    if 'Predicates' in rule:
        for predicate in rule['Predicates']:
            if predicate['Type'] in match_sets:
                predicate.update(match_sets[predicate['Type']](client, predicate['DataId']))
                # replaced by Id from the relevant MatchSet
                del(predicate['DataId'])
    return rule


@AWSRetry.backoff(tries=5, delay=5, backoff=2.0)
def get_web_acl_with_backoff(client, web_acl_id):
    return client.get_web_acl(WebACLId=web_acl_id)


def get_web_acl(client, module, web_acl_id):
    try:
        web_acl = get_web_acl_with_backoff(client, web_acl_id)
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg="Couldn't obtain web acl")

    if web_acl['WebACL']:
        try:
            for rule in web_acl['WebACL']['Rules']:
                rule.update(get_rule(client, module, rule['RuleId']))
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            module.fail_json_aws(e, msg="Couldn't obtain web acl rule")
    return camel_dict_to_snake_dict(web_acl['WebACL'])


@AWSRetry.backoff(tries=5, delay=5, backoff=2.0)
def list_web_acls_with_backoff(client):
    paginator = client.get_paginator('list_web_acls')
    return paginator.paginate().build_full_result()['WebACLs']


def list_web_acls(client, module):
    try:
        return list_web_acls_with_backoff(client)
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg="Couldn't obtain web acls")


def get_change_token(client, module):
    try:
        token = client.get_change_token()
        return token['ChangeToken']
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg='')
