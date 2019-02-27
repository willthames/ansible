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


COMPUTED_SENTINEL = '*** COMPUTED ***'


class AnsibleStateModule(AnsibleModule):

    def __init__(self, **kwargs):
        kwargs['supports_state'] = True
        kwargs['maintains_state'] = True
        default_argument_spec = dict(
            resource_id=dict(),
            depends_on=dict(type='list'),
            _state=dict(type='dict'),
            verify_state=dict(type='bool', default=False),
            enforce_state=dict(type='bool', default=False),
            state=dict(choices=['present', 'absent']),
        )

        argument_spec = kwargs.get('argument_spec', {})
        default_argument_spec.update(argument_spec)
        kwargs['argument_spec'] = default_argument_spec

        super(AnsibleStateModule, self).__init__(**kwargs)
        self.diff_ignore = []
        self.computed_sentinel = COMPUTED_SENTINEL

    def compare(self, before, after):
        if before == after:
            return {}
        if not before:
            return {'before': None, 'after': after}
        if not after:
            return {'before': before, 'after': None}
        left = dict((k, before[k]) for k in set(before.keys()).difference(self.diff_ignore)
                      if before.get(k) != after.get(k))
        right = dict((k, after[k]) for k in set(after.keys()).difference(self.diff_ignore)
                     if before.get(k) != after.get(k))
        return {'before': left, 'after': right}

    def run(self):
        # state strategy will pass in empty dict when no state exists,
        # default is None, so can distinguish between standard and state operation.
        existing = self.params['_state']
        if existing is None:
            existing = self.get()
        elif self.params['verify_state'] or self.params['enforce_state']:
            actual = self.get()
            diff = self.compare(existing, actual)
            if diff:
                if not self.params['enforce_state']:
                    self.fail_json(msg="Validation fail: Actual state does not match recorded state",
                                   actual=actual, existing=existing, diff=diff)
                else:
                    self.warn("Validation warning: Actual state does not match recorded state. diff: %s" % diff)
                    existing = actual

        # override unset parameters from _state
        for param in self.params.get('_state') or {}:
            if param in self.params and self.params[param] is None:
                self.params[param] = self.params['_state'][param]

        state = self.params['state']

        if state == 'present':
            desired = self.predict(existing)
            changed = False
            if existing and existing.get('state', state) == state:
                diff = self.compare(existing, desired)
                if diff:
                    if not self.check_mode:
                        desired = self.update(existing)
                        diff = self.compare(existing, desired)
                        changed = (diff != {})
            else:
                if not self.check_mode:
                    desired = self.create()
                diff = self.compare(existing, desired)
                changed = True
            _state = desired
            _state['state'] = 'present'
            return dict(changed=changed, diff={}, _state=_state, **desired)
        if state == 'absent':
            if existing and 'state' not in existing:
                import epdb
                epdb.st()
            if not existing or existing['state'] == state:
                return dict(changed=False, _state={'state': 'absent'})
            else:
                desired = {'state': 'absent'}
                if not self.check_mode:
                    desired = self.delete(existing)
                diff = self.compare(existing, {})
                return dict(changed=True, diff=diff, _state=desired)
