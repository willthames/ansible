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
module: state_file
short_description: Creates a file with some content
description:
    - Testing module for ansible state capability
version_added: "2.6"
author: Will Thames (@willthames)
options:
  path:
    description:
      - Location of the state file
    required: yes
  content:
    description:
      - Content of the file
'''

EXAMPLES = '''
- state_file:
    path: "{{ tempdir }}/state_file"
    content: 123
    resource_id: my_state_file

- debug:
    msg: "{{ ansible_state.state_file.my_state_file.inode }}"
'''

RETURN = '''
path:
    description: Location of the file
    returned: success
    type: string
    sample: /path/to/file
content:
    description: Content of the file
    returned: success
    type: string
    sample: 123
inode:
    description: Inode of the file
    returned: success
    type: string
    sample: 1234567
'''

from ansible.module_utils.state import AnsibleStateModule
import os
import stat


class StateFileModule(AnsibleStateModule):

    def __init__(self, *args, **kwargs):
        super(StateFileModule, self).__init__(*args, **kwargs)
        self.diff_ignore = ['inode']

    def get(self):
        results = dict()
        path = self.params['path']
        results['path'] = path
        if not os.path.exists(path):
            return {'state': 'absent'}
        path_stat = os.stat(path)
        results['inode'] = path_stat[stat.ST_INO]
        with open(path) as f:
            results['content'] = f.read()
        results['state'] = 'present'
        return results

    def create(self):
        path = self.params['path']
        with open(path, 'w') as f:
            f.write(self.params['content'])
        return self.get()

    def delete(self):
        os.remove(self.params['path'])
        return {'state': 'absent'}

    def predict(self, existing):
        return dict(
            path=self.params['path'],
            content=self.params['content'],
            inode='***COMPUTED***')

    def update(self, existing):
        if self.params['path'] != existing['path']:
            if os.path.exists(existing['path']):
                os.rename(existing['path'], self.params['path'])
            else:
                return self.create()
        if self.params['content'] != existing['content']:
            return self.create()


def main():
    argument_spec = dict(
        path=dict(required=True),
        content=dict(required=True),
    )

    module = StateFileModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )
    module.exit_json(**module.run())


if __name__ == '__main__':
    main()
