# (c) 2017 Will Thames
#
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
# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
    strategy: state
    short_description: Executes tasks based on task dependencies and state
    description:
        - A state file is examined to determine whether tasks are required to run. The order
          of tasks is not necessarily at all related to their order in the file - an ordering
          will be generated based on dependency relationships. Tasks will not run in parallel
          even when possible.
    version_added: "2.6"
    author: Will Thames
'''

from collections import defaultdict
import datetime
import os
import tempfile
import time
import yaml

from ansible import constants as C
from ansible.errors import AnsibleError, AnsibleUndefinedVariable
from ansible.playbook.included_file import IncludedFile
from ansible.plugins.loader import action_loader
from ansible.plugins.strategy import StrategyBase
from ansible.template import Templar
from ansible.module_utils._text import to_text


try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()


class StateNode(object):
    def __init__(self, task, state, resource_id=None):
        self.task = task
        self.state = state
        self.resource_id = resource_id
        self.children = []


class StrategyModule(StrategyBase):

    def resolve_candidates(self, unresolved, ansible_resources):
        result = []
        resolved = []
        for (state, task, task_vars, host) in unresolved:
            try:
                extra_vars = task_vars.copy()
                extra_vars.update(dict(ansible_resources=ansible_resources))
                templar = Templar(loader=self._loader, variables=extra_vars)
                for (k, v) in task.args.items():
                    task.args[k] = to_text(templar.template(v), nonstring='empty')
                display.debug("Adding %s %s to state" % (task.action, task.args.get('resource_id')))

                # Run new task in check mode
                self.run_task(host, task, check_mode=True)
                results = self._process_pending_results(self.iterator)

                if task.args.get('resource_id'):
                    state_node = StateNode(state, task, task.args['resource_id'])
                    ansible_resources[task.action][task.args['resource_id']] = state_node
                else:
                    state_node = StateNode(state, task)
                resolved.append(state_node)
            except AnsibleUndefinedVariable as e:
                # hopefully we can resolve this in a later pass
                pass
            time.sleep(1)
        return resolved, result

    def generate_task_ordering(self):
        hosts = self.get_hosts_left(self.iterator)
        ansible_resources = defaultdict(dict)
        unresolved = list()
        resolved = list()
        for host in hosts:
            while True:
                (state, task) = self.iterator.get_next_task_for_host(host)
                if not task:
                    break
                display.debug("state host state: %s" % state)
                display.debug("state host task: %s" % task)
                display.debug("getting variables")
                task_vars = self._variable_manager.get_vars(play=self.iterator._play, host=host, task=task)
                self.add_tqm_variables(task_vars, play=self.iterator._play)
                display.debug("done getting variables")
                templar = Templar(loader=self._loader, variables=task_vars)
                task.name = to_text(templar.template(task.name, fail_on_undefined=False), nonstring='empty')
                task.args['validate_state'] = task.args.get('validate_state', self.play_context.validate_state)
                task.args['enforce_state'] = task.args.get('enforce_state', self.play_context.enforce_state)
                task.args['state'] = task.args.get('enforce_state', self.play_context.enforce_state)
                unresolved.append((state, task, task_vars, host))

        while unresolved:
            newresolved, unresolved = self.resolve_candidates(unresolved, ansible_resources)
            if not newresolved:
                display.warning("No new resolutions on most recent pass")
            resolved.extend(newresolved)
        return resolved

    def run_task(self, host, task, check_mode=False):
        if check_mode:
            task.check_mode = check_mode
        host_name = host.get_name()
        if host_name not in self._tqm._unreachable_hosts and task:
            # check to see if this host is blocked (still executing a previous task)
            if host_name not in self._blocked_hosts or not self._blocked_hosts[host_name]:
                # pop the task, mark the host blocked, and queue it
                self._blocked_hosts[host_name] = True
                try:
                    action = action_loader.get(task.action, class_only=True)
                except KeyError:
                    # we don't care here, because the action may simply not have a
                    # corresponding action plugin
                    action = None

                display.debug("getting variables")
                task_vars = self._variable_manager.get_vars(play=self.iterator._play, host=host, task=task)
                self.add_tqm_variables(task_vars, play=self.iterator._play)
                templar = Templar(loader=self._loader, variables=task_vars)
                display.debug("done getting variables")

                try:
                    task.name = to_text(templar.template(task.name, fail_on_undefined=False), nonstring='empty')
                    display.debug("done templating")
                except:
                    # just ignore any errors during task name templating,
                    # we don't care if it just shows the raw name
                    display.debug("templating failed for some reason")

                run_once = templar.template(task.run_once) or action and getattr(action, 'BYPASS_HOST_LOOP', False)
                if run_once:
                    if action and getattr(action, 'BYPASS_HOST_LOOP', False):
                        raise AnsibleError("The '%s' module bypasses the host loop, which is currently not supported in the state strategy "
                                           "and would instead execute for every host in the inventory list." % task.action, obj=task._ds)
                    else:
                        display.warning("Using run_once with the state strategy is not currently supported. This task will still be "
                                        "executed for every host in the inventory list.")

                if task.action == 'meta':
                    self._execute_meta(task, self.play_context, self.iterator, target_host=host)
                    self._blocked_hosts[host_name] = False
                else:
                    # handle step if needed, skip meta actions as they are used internally
                    if not self._step or self._take_step(task, host_name):
                        if task.any_errors_fatal:
                            display.warning("Using any_errors_fatal with the free strategy is not supported, "
                                            "as tasks are executed independently on each host")
                        self._tqm.send_callback('v2_playbook_on_task_start', task, is_conditional=False)
                        self._queue_task(host, task, task_vars, self.play_context)
                        del task_vars
            else:
                display.debug("%s is blocked, skipping for now" % host_name)

    def load_ansible_state(self):
        state_file = C.STATE_FILE
        if not state_file:
            raise AnsibleError("Ansible State File needs to be explicitly set when using state strategy")
        if os.path.exists(state_file):
            try:
                with open(state_file) as f:
                    self.ansible_state = yaml.safe_load(f)
            except OSError as e:
                raise AnsibleError("Couldn't read state file %s: " % (state_file, to_text(e)))
        else:
            self.ansible_state = {}

    def save_ansible_state(self):
        state_file = C.STATE_FILE
        try:
            afd, afile = tempfile.mkstemp()
            header = "# ANSIBLE STATE FILE\n# VERSION 0.1\n# DO NOT MODIFY\n# %s" % datetime.datetime.utcnow().isoformat()
            afd.write(header + yaml.safe_dump(self.ansible_state, default_flow_style=False))
            os.rename(afile, state_file)
        except OSError as e:
            raise AnsibleError("Couldn't write to state file %s: %s" % (state_file, to_text(e)))

    def run(self, iterator, play_context):
        '''
        The "state" strategy generates an ordering of tasks across all hosts
        and then runs all of those tasks in order. Although such tasks could be
        independent and run in parallel, this is only likely to happen when tasks
        run independently across hosts.
        '''

        result = self._tqm.RUN_OK

        self.iterator = iterator
        self.play_context = play_context
        self.load_ansible_state()
        ordering = self.generate_task_ordering()

        for (host, task) in ordering:
            self.run_task(host, task)

            results = self._process_pending_results(self.iterator)
            # only modify ansible_state file if different
            # self.save_ansible_state()
            self.update_active_connections(results)

            # pause briefly so we don't spin lock
            time.sleep(C.DEFAULT_INTERNAL_POLL_INTERVAL)

        # collect all the final results
        results = self._wait_on_pending_results(self.iterator)

        # run the base class run() method, which executes the cleanup function
        # and runs any outstanding handlers which have been triggered
        return super(StrategyModule, self).run(self.iterator, self.play_context, result)
