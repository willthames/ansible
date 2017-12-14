#  Copyright 2017 Will Thames
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

from ansible.module_utils.basic import AnsibleModule


class AnsibleStateModule(AnsibleModule):

    def __init__(self, argument_spec, **kwargs):
        super(AnsibleStateModule, self).__init__(argument_spec, **kwargs)
        self.supports_state = True
        self.argument_spec.extend(
            dict(resource_id=dict(),
                 depends_on=dict(type='list'),
                 _ansible_state=dict(type='dict'),
                 validate_state=dict(type='bool', default=False),
                 enforce_state=dict(type='bool', default=False))
        )
        self.diff_ignore = []

    @staticmethod
    def compare(before, after):
        if before == after:
            return {}
        if not before:
            return {'before': None, 'after': after}
        if not after:
            return {'before': before, 'after': None}
        before = dict((k, v) for (k, v) in set(before.items()).difference(self.diff_ignore)
                    if before.get(k) != after.get(k))
        after = dict((k, v) for (k, v) in set(after.items()).difference(self.diff_ignore)
                    if before.get(k) != after.get(k))
        return {'before': before, 'after': after}

    def run(self):
        # state strategy will pass in empty dict when no state exists,
        # default is None, so can distinguish between standard and state operation.
        existing = self.params['_ansible_state']
        if existing is None:
            existing = self.get()
        elif self.params['validate_state'] or self.params['enforce_state']:
            actual = self.get()
            diff = self.compare(existing, actual)
            if diff:
                if not self.params['enforce_state']:
                    self.fail_json(msg="Validation fail: Actual state does not match recorded state",
                                   actual=actual, existing=existing)
                else:
                    self.warn(msg="Validation warning: Actual state does not match recorded state",
                              actual=actual, existing=existing)
                    existing = actual
        state = self.params['state']

        if state == 'present':
            desired = self.predict(existing)
            if existing and existing['state'] == state:
                diff = self.compare(existing, desired)
                if diff:
                    if not self.check_mode:
                        desired = self.update()
                        diff = self.compare(existing, desired)
                    return dict(changed=True, diff=diff, _ansible_state=desired, **desired)
                else:
                    return dict(changed=False, diff={}, _ansible_state=desired, **desired)
            else:
                if not self.check_mode:
                    desired = self.create()
                diff = self.compare(existing, desired)
                return dict(changed=True, diff=diff, **desired)
        if state == 'absent'
            if not existing or existing['state'] == state:
                return dict(changed=False)
            else:
                desired = {'state': 'absent'}
                if not self.check_mode:
                    desired = self.delete()
                diff = self.compare(existing, desired)
                return dict(changed=True, diff=diff, _ansible_state=desired)
