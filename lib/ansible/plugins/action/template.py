# (c) 2015, Michael DeHaan <michael.dehaan@gmail.com>
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
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import datetime
import os
import pwd
import time

from ansible import constants as C
from ansible.plugins.action import ActionBase
from ansible.utils.hashing import checksum_s
from ansible.utils.boolean import boolean
from ansible.utils.unicode import to_bytes, to_unicode


class ActionModule(ActionBase):

    TRANSFERS_FILES = True

    def get_checksum(self, dest, all_vars, try_directory=False, source=None, tmp=None):
        try:
            dest_stat = self._execute_remote_stat(dest, all_vars=all_vars, follow=False, tmp=tmp)

            if dest_stat['exists'] and dest_stat['isdir'] and try_directory and source:
                base = os.path.basename(source)
                dest = os.path.join(dest, base)
                dest_stat = self._execute_remote_stat(dest, all_vars=all_vars, follow=False, tmp=tmp)

        except Exception as e:
            return dict(failed=True, msg=to_bytes(e))

        return dest_stat['checksum']

    def run(self, tmp=None, task_vars=None):
        ''' handler for template operations '''
        if task_vars is None:
            task_vars = dict()

        result = super(ActionModule, self).run(tmp, task_vars)

        source = self._task.args.get('src', None)
        dest   = self._task.args.get('dest', None)
        faf    = self._task.first_available_file
        force  = boolean(self._task.args.get('force', True))
        state  = self._task.args.get('state', None)

        if state is not None:
            result['failed'] = True
            result['msg'] = "'state' cannot be specified on a template"
            return result
        elif (source is None and faf is not None) or dest is None:
            result['failed'] = True
            result['msg'] = "src and dest are required"
            return result

        if faf:
            source = self._get_first_available_file(faf, task_vars.get('_original_file', None, 'templates'))
            if source is None:
                result['failed'] = True
                result['msg'] = "could not find src in first_available_file list"
                return result
        else:
            if self._task._role is not None:
                source = self._loader.path_dwim_relative(self._task._role._role_path, 'templates', source)
            else:
                source = self._loader.path_dwim_relative(self._loader.get_basedir(), 'templates', source)

        # Expand any user home dir specification
        dest = self._remote_expand_user(dest)

        directory_prepended = False
        if dest.endswith(os.sep):
            directory_prepended = True
            base = os.path.basename(source)
            dest = os.path.join(dest, base)

        # template the source data locally & get ready to transfer
        try:
            with open(source, 'r') as f:
                template_data = to_unicode(f.read())

            try:
                template_uid = pwd.getpwuid(os.stat(source).st_uid).pw_name
            except:
                template_uid = os.stat(source).st_uid

            temp_vars = task_vars.copy()
            temp_vars['template_host']     = os.uname()[1]
            temp_vars['template_path']     = source
            temp_vars['template_mtime']    = datetime.datetime.fromtimestamp(os.path.getmtime(source))
            temp_vars['template_uid']      = template_uid
            temp_vars['template_fullpath'] = os.path.abspath(source)
            temp_vars['template_run_date'] = datetime.datetime.now()

            managed_default = C.DEFAULT_MANAGED_STR
            managed_str = managed_default.format(
                host = temp_vars['template_host'],
                uid  = temp_vars['template_uid'],
                file = to_bytes(temp_vars['template_path'])
            )
            temp_vars['ansible_managed'] = time.strftime(
                managed_str,
                time.localtime(os.path.getmtime(source))
            )

            # Create a new searchpath list to assign to the templar environment's file
            # loader, so that it knows about the other paths to find template files
            searchpath = [self._loader._basedir, os.path.dirname(source)]
            if self._task._role is not None:
                if C.DEFAULT_ROLES_PATH:
                    searchpath[:0] = C.DEFAULT_ROLES_PATH
                searchpath.insert(1, self._task._role._role_path)

            self._templar.environment.loader.searchpath = searchpath

            old_vars = self._templar._available_variables
            self._templar.set_available_variables(temp_vars)
            resultant = self._templar.template(template_data, preserve_trailing_newlines=True, escape_backslashes=False, convert_data=False)
            self._templar.set_available_variables(old_vars)
        except Exception as e:
            result['failed'] = True
            result['msg'] = type(e).__name__ + ": " + str(e)
            return result

        cleanup_remote_tmp = False
        remote_user = task_vars.get('ansible_ssh_user') or self._play_context.remote_user
        if not tmp:
            tmp = self._make_tmp_path(remote_user)
            cleanup_remote_tmp = True

        new_module_args = self._task.args.copy()

        # run the copy module
        new_module_args.update(
            dict(
                src=source,
                content=resultant,
                dest=dest,
                original_basename=os.path.basename(source),
                follow=True,
            ),
        )
        result.update(self._execute_module(module_name='copy', module_args=new_module_args, task_vars=task_vars, tmp=tmp, delete_remote_tmp=False))

        return result
