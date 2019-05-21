#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 Google
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# ----------------------------------------------------------------------------
#
#     ***     AUTO GENERATED CODE    ***    AUTO GENERATED CODE     ***
#
# ----------------------------------------------------------------------------
#
#     This file is automatically generated by Magic Modules and manual
#     changes will be clobbered when the file is regenerated.
#
#     Please read more about how to change this file at
#     https://www.github.com/GoogleCloudPlatform/magic-modules
#
# ----------------------------------------------------------------------------

from __future__ import absolute_import, division, print_function

__metaclass__ = type

################################################################################
# Documentation
################################################################################

ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ["preview"], 'supported_by': 'community'}

DOCUMENTATION = '''
---
module: gcp_pubsub_subscription
description:
- A named resource representing the stream of messages from a single, specific topic,
  to be delivered to the subscribing application.
short_description: Creates a GCP Subscription
version_added: 2.6
author: Google Inc. (@googlecloudplatform)
requirements:
- python >= 2.6
- requests >= 2.18.4
- google-auth >= 1.3.0
options:
  state:
    description:
    - Whether the given object should exist in GCP
    choices:
    - present
    - absent
    default: present
  name:
    description:
    - Name of the subscription.
    required: true
  topic:
    description:
    - A reference to a Topic resource.
    - 'This field represents a link to a Topic resource in GCP. It can be specified
      in two ways. First, you can place a dictionary with key ''name'' and value of
      your resource''s name Alternatively, you can add `register: name-of-resource`
      to a gcp_pubsub_topic task and then set this topic field to "{{ name-of-resource
      }}"'
    required: true
  labels:
    description:
    - A set of key/value label pairs to assign to this Subscription.
    required: false
    version_added: 2.8
  push_config:
    description:
    - If push delivery is used with this subscription, this field is used to configure
      it. An empty pushConfig signifies that the subscriber will pull and ack messages
      using API methods.
    required: false
    suboptions:
      push_endpoint:
        description:
        - A URL locating the endpoint to which messages should be pushed.
        - For example, a Webhook endpoint might use "U(https://example.com/push".)
        required: true
      attributes:
        description:
        - Endpoint configuration attributes.
        - Every endpoint has a set of API supported attributes that can be used to
          control different aspects of the message delivery.
        - The currently supported attribute is x-goog-version, which you can use to
          change the format of the pushed message. This attribute indicates the version
          of the data expected by the endpoint. This controls the shape of the pushed
          message (i.e., its fields and metadata). The endpoint version is based on
          the version of the Pub/Sub API.
        - If not present during the subscriptions.create call, it will default to
          the version of the API used to make such call. If not present during a subscriptions.modifyPushConfig
          call, its value will not be changed. subscriptions.get calls will always
          return a valid version, even if the subscription was created without this
          attribute.
        - 'The possible values for this attribute are: - v1beta1: uses the push format
          defined in the v1beta1 Pub/Sub API.'
        - "- v1 or v1beta2: uses the push format defined in the v1 Pub/Sub API."
        required: false
  ack_deadline_seconds:
    description:
    - This value is the maximum time after a subscriber receives a message before
      the subscriber should acknowledge the message. After message delivery but before
      the ack deadline expires and before the message is acknowledged, it is an outstanding
      message and will not be delivered again during that time (on a best-effort basis).
    - For pull subscriptions, this value is used as the initial value for the ack
      deadline. To override this value for a given message, call subscriptions.modifyAckDeadline
      with the corresponding ackId if using pull. The minimum custom deadline you
      can specify is 10 seconds. The maximum custom deadline you can specify is 600
      seconds (10 minutes).
    - If this parameter is 0, a default value of 10 seconds is used.
    - For push delivery, this value is also used to set the request timeout for the
      call to the push endpoint.
    - If the subscriber never acknowledges the message, the Pub/Sub system will eventually
      redeliver the message.
    required: false
  message_retention_duration:
    description:
    - How long to retain unacknowledged messages in the subscription's backlog, from
      the moment a message is published. If retainAckedMessages is true, then this
      also configures the retention of acknowledged messages, and thus configures
      how far back in time a subscriptions.seek can be done. Defaults to 7 days. Cannot
      be more than 7 days (`"604800s"`) or less than 10 minutes (`"600s"`).
    - 'A duration in seconds with up to nine fractional digits, terminated by ''s''.
      Example: `"600.5s"`.'
    required: false
    default: 604800s
    version_added: 2.8
  retain_acked_messages:
    description:
    - Indicates whether to retain acknowledged messages. If `true`, then messages
      are not expunged from the subscription's backlog, even if they are acknowledged,
      until they fall out of the messageRetentionDuration window.
    required: false
    type: bool
    version_added: 2.8
  expiration_policy:
    description:
    - A policy that specifies the conditions for this subscription's expiration.
    - A subscription is considered active as long as any connected subscriber is successfully
      consuming messages from the subscription or is issuing operations on the subscription.
      If expirationPolicy is not set, a default policy with ttl of 31 days will be
      used. The minimum allowed value for expirationPolicy.ttl is 1 day.
    required: false
    version_added: 2.9
    suboptions:
      ttl:
        description:
        - Specifies the "time-to-live" duration for an associated resource. The resource
          expires if it is not active for a period of ttl. The definition of "activity"
          depends on the type of the associated resource. The minimum and maximum
          allowed values for ttl depend on the type of the associated resource, as
          well. If ttl is not set, the associated resource never expires.
        - A duration in seconds with up to nine fractional digits, terminated by 's'.
        - Example - "3.5s".
        required: false
extends_documentation_fragment: gcp
notes:
- 'API Reference: U(https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.subscriptions)'
- 'Managing Subscriptions: U(https://cloud.google.com/pubsub/docs/admin#managing_subscriptions)'
'''

EXAMPLES = '''
- name: create a topic
  gcp_pubsub_topic:
    name: topic-subscription
    project: "{{ gcp_project }}"
    auth_kind: "{{ gcp_cred_kind }}"
    service_account_file: "{{ gcp_cred_file }}"
    state: present
  register: topic

- name: create a subscription
  gcp_pubsub_subscription:
    name: test_object
    topic: "{{ topic }}"
    ack_deadline_seconds: 300
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
'''

RETURN = '''
name:
  description:
  - Name of the subscription.
  returned: success
  type: str
topic:
  description:
  - A reference to a Topic resource.
  returned: success
  type: dict
labels:
  description:
  - A set of key/value label pairs to assign to this Subscription.
  returned: success
  type: dict
pushConfig:
  description:
  - If push delivery is used with this subscription, this field is used to configure
    it. An empty pushConfig signifies that the subscriber will pull and ack messages
    using API methods.
  returned: success
  type: complex
  contains:
    pushEndpoint:
      description:
      - A URL locating the endpoint to which messages should be pushed.
      - For example, a Webhook endpoint might use "U(https://example.com/push".)
      returned: success
      type: str
    attributes:
      description:
      - Endpoint configuration attributes.
      - Every endpoint has a set of API supported attributes that can be used to control
        different aspects of the message delivery.
      - The currently supported attribute is x-goog-version, which you can use to
        change the format of the pushed message. This attribute indicates the version
        of the data expected by the endpoint. This controls the shape of the pushed
        message (i.e., its fields and metadata). The endpoint version is based on
        the version of the Pub/Sub API.
      - If not present during the subscriptions.create call, it will default to the
        version of the API used to make such call. If not present during a subscriptions.modifyPushConfig
        call, its value will not be changed. subscriptions.get calls will always return
        a valid version, even if the subscription was created without this attribute.
      - 'The possible values for this attribute are: - v1beta1: uses the push format
        defined in the v1beta1 Pub/Sub API.'
      - "- v1 or v1beta2: uses the push format defined in the v1 Pub/Sub API."
      returned: success
      type: dict
ackDeadlineSeconds:
  description:
  - This value is the maximum time after a subscriber receives a message before the
    subscriber should acknowledge the message. After message delivery but before the
    ack deadline expires and before the message is acknowledged, it is an outstanding
    message and will not be delivered again during that time (on a best-effort basis).
  - For pull subscriptions, this value is used as the initial value for the ack deadline.
    To override this value for a given message, call subscriptions.modifyAckDeadline
    with the corresponding ackId if using pull. The minimum custom deadline you can
    specify is 10 seconds. The maximum custom deadline you can specify is 600 seconds
    (10 minutes).
  - If this parameter is 0, a default value of 10 seconds is used.
  - For push delivery, this value is also used to set the request timeout for the
    call to the push endpoint.
  - If the subscriber never acknowledges the message, the Pub/Sub system will eventually
    redeliver the message.
  returned: success
  type: int
messageRetentionDuration:
  description:
  - How long to retain unacknowledged messages in the subscription's backlog, from
    the moment a message is published. If retainAckedMessages is true, then this also
    configures the retention of acknowledged messages, and thus configures how far
    back in time a subscriptions.seek can be done. Defaults to 7 days. Cannot be more
    than 7 days (`"604800s"`) or less than 10 minutes (`"600s"`).
  - 'A duration in seconds with up to nine fractional digits, terminated by ''s''.
    Example: `"600.5s"`.'
  returned: success
  type: str
retainAckedMessages:
  description:
  - Indicates whether to retain acknowledged messages. If `true`, then messages are
    not expunged from the subscription's backlog, even if they are acknowledged, until
    they fall out of the messageRetentionDuration window.
  returned: success
  type: bool
expirationPolicy:
  description:
  - A policy that specifies the conditions for this subscription's expiration.
  - A subscription is considered active as long as any connected subscriber is successfully
    consuming messages from the subscription or is issuing operations on the subscription.
    If expirationPolicy is not set, a default policy with ttl of 31 days will be used.
    The minimum allowed value for expirationPolicy.ttl is 1 day.
  returned: success
  type: complex
  contains:
    ttl:
      description:
      - Specifies the "time-to-live" duration for an associated resource. The resource
        expires if it is not active for a period of ttl. The definition of "activity"
        depends on the type of the associated resource. The minimum and maximum allowed
        values for ttl depend on the type of the associated resource, as well. If
        ttl is not set, the associated resource never expires.
      - A duration in seconds with up to nine fractional digits, terminated by 's'.
      - Example - "3.5s".
      returned: success
      type: str
'''

################################################################################
# Imports
################################################################################

from ansible.module_utils.gcp_utils import navigate_hash, GcpSession, GcpModule, GcpRequest, remove_nones_from_dict, replace_resource_dict
import json

################################################################################
# Main
################################################################################


def main():
    """Main function"""

    module = GcpModule(
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            name=dict(required=True, type='str'),
            topic=dict(required=True, type='dict'),
            labels=dict(type='dict'),
            push_config=dict(type='dict', options=dict(push_endpoint=dict(required=True, type='str'), attributes=dict(type='dict'))),
            ack_deadline_seconds=dict(type='int'),
            message_retention_duration=dict(default='604800s', type='str'),
            retain_acked_messages=dict(type='bool'),
            expiration_policy=dict(type='dict', options=dict(ttl=dict(type='str'))),
        )
    )

    if not module.params['scopes']:
        module.params['scopes'] = ['https://www.googleapis.com/auth/pubsub']

    state = module.params['state']

    fetch = fetch_resource(module, self_link(module))
    changed = False

    if fetch:
        if state == 'present':
            if is_different(module, fetch):
                update(module, self_link(module), fetch)
                fetch = fetch_resource(module, self_link(module))
                changed = True
        else:
            delete(module, self_link(module))
            fetch = {}
            changed = True
    else:
        if state == 'present':
            fetch = create(module, self_link(module))
            changed = True
        else:
            fetch = {}

    fetch.update({'changed': changed})

    module.exit_json(**fetch)


def create(module, link):
    auth = GcpSession(module, 'pubsub')
    return return_if_object(module, auth.put(link, resource_to_request(module)))


def update(module, link, fetch):
    auth = GcpSession(module, 'pubsub')
    params = {'updateMask': updateMask(resource_to_request(module), response_to_hash(module, fetch))}
    request = resource_to_request(module)
    del request['name']
    return return_if_object(module, auth.patch(link, request, params=params))


def updateMask(request, response):
    update_mask = []
    if request.get('labels') != response.get('labels'):
        update_mask.append('labels')
    if request.get('pushConfig') != response.get('pushConfig'):
        update_mask.append('pushConfig')
    if request.get('ackDeadlineSeconds') != response.get('ackDeadlineSeconds'):
        update_mask.append('ackDeadlineSeconds')
    if request.get('messageRetentionDuration') != response.get('messageRetentionDuration'):
        update_mask.append('messageRetentionDuration')
    if request.get('retainAckedMessages') != response.get('retainAckedMessages'):
        update_mask.append('retainAckedMessages')
    if request.get('expirationPolicy') != response.get('expirationPolicy'):
        update_mask.append('expirationPolicy')
    return ','.join(update_mask)


def delete(module, link):
    auth = GcpSession(module, 'pubsub')
    return return_if_object(module, auth.delete(link))


def resource_to_request(module):
    request = {
        u'name': module.params.get('name'),
        u'topic': replace_resource_dict(module.params.get(u'topic', {}), 'name'),
        u'labels': module.params.get('labels'),
        u'pushConfig': SubscriptionPushconfig(module.params.get('push_config', {}), module).to_request(),
        u'ackDeadlineSeconds': module.params.get('ack_deadline_seconds'),
        u'messageRetentionDuration': module.params.get('message_retention_duration'),
        u'retainAckedMessages': module.params.get('retain_acked_messages'),
        u'expirationPolicy': SubscriptionExpirationpolicy(module.params.get('expiration_policy', {}), module).to_request(),
    }
    request = encode_request(request, module)
    return_vals = {}
    for k, v in request.items():
        if v or v is False:
            return_vals[k] = v

    return return_vals


def fetch_resource(module, link, allow_not_found=True):
    auth = GcpSession(module, 'pubsub')
    return return_if_object(module, auth.get(link), allow_not_found)


def self_link(module):
    return "https://pubsub.googleapis.com/v1/projects/{project}/subscriptions/{name}".format(**module.params)


def collection(module):
    return "https://pubsub.googleapis.com/v1/projects/{project}/subscriptions".format(**module.params)


def return_if_object(module, response, allow_not_found=False):
    # If not found, return nothing.
    if allow_not_found and response.status_code == 404:
        return None

    # If no content, return nothing.
    if response.status_code == 204:
        return None

    try:
        module.raise_for_status(response)
        result = response.json()
    except getattr(json.decoder, 'JSONDecodeError', ValueError):
        module.fail_json(msg="Invalid JSON response with error: %s" % response.text)

    result = decode_request(result, module)

    if navigate_hash(result, ['error', 'errors']):
        module.fail_json(msg=navigate_hash(result, ['error', 'errors']))

    return result


def is_different(module, response):
    request = resource_to_request(module)
    response = response_to_hash(module, response)
    request = decode_request(request, module)

    # Remove all output-only from response.
    response_vals = {}
    for k, v in response.items():
        if k in request:
            response_vals[k] = v

    request_vals = {}
    for k, v in request.items():
        if k in response:
            request_vals[k] = v

    return GcpRequest(request_vals) != GcpRequest(response_vals)


# Remove unnecessary properties from the response.
# This is for doing comparisons with Ansible's current parameters.
def response_to_hash(module, response):
    return {
        u'name': module.params.get('name'),
        u'topic': replace_resource_dict(module.params.get(u'topic', {}), 'name'),
        u'labels': response.get(u'labels'),
        u'pushConfig': SubscriptionPushconfig(response.get(u'pushConfig', {}), module).from_response(),
        u'ackDeadlineSeconds': response.get(u'ackDeadlineSeconds'),
        u'messageRetentionDuration': response.get(u'messageRetentionDuration'),
        u'retainAckedMessages': response.get(u'retainAckedMessages'),
        u'expirationPolicy': SubscriptionExpirationpolicy(response.get(u'expirationPolicy', {}), module).from_response(),
    }


def decode_request(response, module):
    if 'name' in response:
        response['name'] = response['name'].split('/')[-1]

    if 'topic' in response:
        response['topic'] = response['topic'].split('/')[-1]

    return response


def encode_request(request, module):
    request['topic'] = '/'.join(['projects', module.params['project'], 'topics', request['topic']])
    request['name'] = '/'.join(['projects', module.params['project'], 'subscriptions', module.params['name']])

    return request


class SubscriptionPushconfig(object):
    def __init__(self, request, module):
        self.module = module
        if request:
            self.request = request
        else:
            self.request = {}

    def to_request(self):
        return remove_nones_from_dict({u'pushEndpoint': self.request.get('push_endpoint'), u'attributes': self.request.get('attributes')})

    def from_response(self):
        return remove_nones_from_dict({u'pushEndpoint': self.request.get(u'pushEndpoint'), u'attributes': self.request.get(u'attributes')})


class SubscriptionExpirationpolicy(object):
    def __init__(self, request, module):
        self.module = module
        if request:
            self.request = request
        else:
            self.request = {}

    def to_request(self):
        return remove_nones_from_dict({u'ttl': self.request.get('ttl')})

    def from_response(self):
        return remove_nones_from_dict({u'ttl': self.request.get(u'ttl')})


if __name__ == '__main__':
    main()
