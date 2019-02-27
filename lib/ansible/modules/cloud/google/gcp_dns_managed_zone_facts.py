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
module: gcp_dns_managed_zone_facts
description:
- Gather facts for GCP ManagedZone
short_description: Gather facts for GCP ManagedZone
version_added: 2.8
author: Google Inc. (@googlecloudplatform)
requirements:
- python >= 2.6
- requests >= 2.18.4
- google-auth >= 1.3.0
options:
  dns_name:
    description:
    - Restricts the list to return only zones with this domain name.
extends_documentation_fragment: gcp
'''

EXAMPLES = '''
- name: " a managed zone facts"
  gcp_dns_managed_zone_facts:
    dns_name: test.somewild2.example.com.
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: facts
'''

RETURN = '''
items:
  description: List of items
  returned: always
  type: complex
  contains:
    description:
      description:
      - A mutable string of at most 1024 characters associated with this resource
        for the user's convenience. Has no effect on the managed zone's function.
      returned: success
      type: str
    dnsName:
      description:
      - The DNS name of this managed zone, for instance "example.com.".
      returned: success
      type: str
    id:
      description:
      - Unique identifier for the resource; defined by the server.
      returned: success
      type: int
    name:
      description:
      - User assigned name for this resource.
      - Must be unique within the project.
      returned: success
      type: str
    nameServers:
      description:
      - Delegate your managed_zone to these virtual name servers; defined by the server
        .
      returned: success
      type: list
    nameServerSet:
      description:
      - Optionally specifies the NameServerSet for this ManagedZone. A NameServerSet
        is a set of DNS name servers that all host the same ManagedZones. Most users
        will leave this field unset.
      returned: success
      type: list
    creationTime:
      description:
      - The time that this resource was created on the server.
      - This is in RFC3339 text format.
      returned: success
      type: str
    labels:
      description:
      - A set of key/value label pairs to assign to this ManagedZone.
      returned: success
      type: dict
'''

################################################################################
# Imports
################################################################################
from ansible.module_utils.gcp_utils import navigate_hash, GcpSession, GcpModule, GcpRequest
import json

################################################################################
# Main
################################################################################


def main():
    module = GcpModule(argument_spec=dict(dns_name=dict(type='list', elements='str')))

    if not module.params['scopes']:
        module.params['scopes'] = ['https://www.googleapis.com/auth/ndev.clouddns.readwrite']

    items = fetch_list(module, collection(module), module.params['dns_name'])
    if items.get('managedZones'):
        items = items.get('managedZones')
    else:
        items = []
    return_value = {'items': items}
    module.exit_json(**return_value)


def collection(module):
    return "https://www.googleapis.com/dns/v1/projects/{project}/managedZones".format(**module.params)


def fetch_list(module, link, query):
    auth = GcpSession(module, 'dns')
    response = auth.get(link, params={'dnsName': query})
    return return_if_object(module, response)


def return_if_object(module, response):
    # If not found, return nothing.
    if response.status_code == 404:
        return None

    # If no content, return nothing.
    if response.status_code == 204:
        return None

    try:
        module.raise_for_status(response)
        result = response.json()
    except getattr(json.decoder, 'JSONDecodeError', ValueError) as inst:
        module.fail_json(msg="Invalid JSON response with error: %s" % inst)

    if navigate_hash(result, ['error', 'errors']):
        module.fail_json(msg=navigate_hash(result, ['error', 'errors']))

    return result


if __name__ == "__main__":
    main()
