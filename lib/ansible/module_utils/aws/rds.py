# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible. If not, see <http://www.gnu.org/licenses/>.

try:
    import botocore
except ImportError:
    pass

from ansible.module_utils.ec2 import camel_dict_to_snake_dict


def get_db_instance(conn, instancename):
    try:
        response = conn.describe_db_instances(DBInstanceIdentifier=instancename)
        instance = RDSDBInstance(response['DBInstances'][0])
        return camel_dict_to_snake_dict(response['DBinstances'][0])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'DBInstanceNotFound':
            return None


def get_db_snapshot(conn, snapshotid):
    try:
        response = conn.describe_db_snapshots(DBSnapshotIdentifier=snapshotid)
        return camel_dict_to_snake_dict(response['DBSnapshots'][0])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'DBSnapshotNotFound':
            return None


def rds_instance_diff(instance1, instance2):
    # FIXME compare_keys should be all things that can be modified
    # except port and instance_name which are handled separately
    # valid_vars = ['backup_retention', 'backup_window',
    #               'db_name',  'db_engine', 'engine_version',
    #               'instance_type', 'iops', 'license_model',
    #               'maint_window', 'multi_zone', 'new_instance_name',
    #               'option_group', 'parameter_group', 'password', 'size',
    #               'storage_type', 'subnet', 'tags', 'upgrade', 'username',
    #               'vpc_security_groups']
    compare_keys = ['backup_retention', 'instance_type', 'iops',
                    'maintenance_window', 'multi_zone',
                    'replication_source',
                    'size', 'storage_type', 'tags', 'zone']
    leave_if_null = ['maintenance_window', 'backup_retention']
    before = dict()
    after = dict()
    for k in compare_keys:
        if instance1.get(k) != instance2.get(k):
            if instance2.get(k) is None and k in leave_if_null:
                pass
            else:
                before[k] = instance1.get(k)
                after[k] = instance2.get(k)
    old_port = instance1.get("endpoint", {}).get("port")
    new_port = instance2.get("endpoint", {}).get("port")
    if old_port != new_port:
        before['port'] = old_port
        after['port'] = new_port
    result = dict()
    if before:
        result = dict(before_header=self.name, before=before, after=after)
        result['after_header'] = instance2.get('new_instance_name', instance2.get('instance_name'))
    return result
