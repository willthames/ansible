#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: ecs_task
short_description: run, start or stop a task in ecs
description:
    - Creates or deletes instances of task definitions.
version_added: "2.0"
author: Mark Chance(@Java1Guy)
requirements: [ json, botocore, boto3 ]
options:
    operation:
        description:
            - Which task operation to execute
        required: True
        choices: ['run', 'start', 'stop']
    cluster:
        description:
            - The name of the cluster to run the task on
        required: False
    task_definition:
        description:
            - The task definition to start or run
        required: True
    overrides:
        description:
            - A dictionary of values to pass to the new instances
        required: False
    count:
        description:
            - How many new instances to start
        required: False
    task:
        description:
            - The task to stop
        required: False
    container_instances:
        description:
            - The list of container instances on which to deploy the task
        required: False
    started_by:
        description:
            - A value showing who or what started the task (for informational purposes)
        required: False
extends_documentation_fragment:
    - aws
    - ec2
'''

EXAMPLES = '''
# Simple example of run task
- name: Run task
  ecs_task:
    operation: run
    cluster: console-sample-app-static-cluster
    task_definition: console-sample-app-static-taskdef
    count: 1
    started_by: ansible_user
  register: task_output

# Simple example of start task

- name: Start a task
  ecs_task:
      operation: start
      cluster: console-sample-app-static-cluster
      task_definition: console-sample-app-static-taskdef
      task: "arn:aws:ecs:us-west-2:172139249013:task/3f8353d1-29a8-4689-bbf6-ad79937ffe8a"
      container_instances:
      - arn:aws:ecs:us-west-2:172139249013:container-instance/79c23f22-876c-438a-bddf-55c98a3538a8
      started_by: ansible_user
  register: task_output

- name: Stop a task
  ecs_task:
      operation: stop
      cluster: console-sample-app-static-cluster
      task_definition: console-sample-app-static-taskdef
      task: "arn:aws:ecs:us-west-2:172139249013:task/3f8353d1-29a8-4689-bbf6-ad79937ffe8a"
'''
RETURN = '''
task:
    description: details about the tast that was started
    returned: success
    type: complex
    contains:
        taskArn:
            description: The Amazon Resource Name (ARN) that identifies the task.
            returned: always
            type: string
        clusterArn:
            description: The Amazon Resource Name (ARN) of the of the cluster that hosts the task.
            returned: only when details is true
            type: string
        taskDefinitionArn:
            description: The Amazon Resource Name (ARN) of the task definition.
            returned: only when details is true
            type: string
        containerInstanceArn:
            description: The Amazon Resource Name (ARN) of the container running the task.
            returned: only when details is true
            type: string
        overrides:
            description: The container overrides set for this task.
            returned: only when details is true
            type: list of complex
        lastStatus:
            description: The last recorded status of the task.
            returned: only when details is true
            type: string
        desiredStatus:
            description: The desired status of the task.
            returned: only when details is true
            type: string
        containers:
            description: The container details.
            returned: only when details is true
            type: list of complex
        startedBy:
            description: The used who started the task.
            returned: only when details is true
            type: string
        stoppedReason:
            description: The reason why the task was stopped.
            returned: only when details is true
            type: string
        createdAt:
            description: The timestamp of when the task was created.
            returned: only when details is true
            type: string
        startedAt:
            description: The timestamp of when the task was started.
            returned: only when details is true
            type: string
        stoppedAt:
            description: The timestamp of when the task was stopped.
            returned: only when details is true
            type: string
'''

try:
    import botocore
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import boto3_conn, ec2_argument_spec, get_aws_connection_info


class EcsExecManager:
    """Handles ECS Tasks"""

    def __init__(self, module):
        self.module = module

        region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
        self.ecs = boto3_conn(module, conn_type='client', resource='ecs', region=region, endpoint=ec2_url, **aws_connect_kwargs)

    def list_tasks(self, cluster_name, task_definition, status):
        family = ':'.join(task_definition.split(':')[:-1])
        response = self.ecs.list_tasks(
            cluster=cluster_name,
            family=family,
            desiredStatus=status
        )
        if len(response['taskArns']) > 0:
            for c in response['taskArns']:
                if c.endswith(task_definition):
                    return c
        return None

    def run_task(self, cluster, task_definition, overrides, count, startedBy):
        if overrides is None:
            overrides = dict()
        response = self.ecs.run_task(
            cluster=cluster,
            taskDefinition=task_definition,
            overrides=overrides,
            count=count,
            startedBy=startedBy)
        # include tasks and failures
        return response['tasks'], response['failures']

    def start_task(self, cluster, task_definition, overrides, container_instances, startedBy):
        args = dict()
        if cluster:
            args['cluster'] = cluster
        if task_definition:
            args['taskDefinition'] = task_definition
        if overrides:
            args['overrides'] = overrides
        if container_instances:
            args['containerInstances'] = container_instances
        if startedBy:
            args['startedBy'] = startedBy
        response = self.ecs.start_task(**args)
        # include tasks and failures
        return response['tasks']

    def stop_task(self, cluster, task):
        response = self.ecs.stop_task(cluster=cluster, task=task)
        return response['task']


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        operation=dict(required=True, choices=['run', 'start', 'stop']),
        cluster=dict(required=False, type='str'),  # R S P
        task_definition=dict(required=True, type='str'),  # R* S*
        overrides=dict(required=False, type='dict'),  # R S
        count=dict(required=False, type='int'),  # R
        task=dict(required=False, type='str'),  # P*
        container_instances=dict(required=False, type='list'),  # S*
        started_by=dict(required=False, type='str')  # R S
    ))

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_if=[['operation', 'start', ['container_instances']],
                                        ['operation', 'stop', ['task']]])

    # Validate Requirements
    if not HAS_BOTO3:
        module.fail_json(msg='boto3 is required.')

    # Validate Inputs
    if module.params['operation'] == 'run':
        task_to_list = module.params['task_definition']
        status_type = "RUNNING"

    if module.params['operation'] == 'start':
        task_to_list = module.params['task']
        status_type = "RUNNING"

    if module.params['operation'] == 'stop':
        task_to_list = module.params['task_definition']
        status_type = "STOPPED"

    service_mgr = EcsExecManager(module)
    existing = service_mgr.list_tasks(module.params['cluster'], task_to_list, status_type)

    results = dict(changed=False)
    if module.params['operation'] == 'run':
        if existing:
            # TBD - validate the rest of the details
            results['task'] = existing
        else:
            if not module.check_mode:
                results['tasks'], results['failures'] = service_mgr.run_task(
                    module.params['cluster'],
                    module.params['task_definition'],
                    module.params['overrides'],
                    module.params['count'],
                    module.params['started_by'])
            if results['failures']:
                module.fail_json(msg="Couldn't run task", **results)
            results['changed'] = True

    elif module.params['operation'] == 'start':
        if existing:
            # TBD - validate the rest of the details
            results['task'] = existing
        else:
            if not module.check_mode:
                results['task'] = service_mgr.start_task(
                    module.params['cluster'],
                    module.params['task_definition'],
                    module.params['overrides'],
                    module.params['container_instances'],
                    module.params['started_by']
                )
            results['changed'] = True

    elif module.params['operation'] == 'stop':
        if existing:
            results['task'] = existing
        else:
            if not module.check_mode:
                # it exists, so we should delete it and mark changed.
                # return info about the cluster deleted
                results['task'] = service_mgr.stop_task(
                    module.params['cluster'],
                    module.params['task']
                )
            results['changed'] = True

    module.exit_json(**results)


if __name__ == '__main__':
    main()
