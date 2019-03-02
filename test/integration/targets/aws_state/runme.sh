#!/usr/bin/env bash

# We don't set -u here, due to pypa/virtualenv#150
set -ex

MYTMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'mytmpdir')

function run_test() {
  name=$1
  shift
  echo "**** RUNNING $name ****"
  cmd="ansible-playbook -e tempdir=$MYTMPDIR -e resource_prefix=$(basename $MYTMPDIR) -v $@"
  echo ANSIBLE_KEEP_REMOTE_FILES=1 ANSIBLE_STATE_FILE=$MYTMPDIR/ansible.state $cmd
  ANSIBLE_KEEP_REMOTE_FILES=1 ANSIBLE_STATE_FILE=$MYTMPDIR/ansible.state $cmd
  rc=$?
  echo $rc
  return $rc
}

trap 'rm -rf "${MYTMPDIR}"' EXIT

# This is needed for the ubuntu1604py3 tests
# Ubuntu patches virtualenv to make the default python2
# but for the python3 tests we need virtualenv to use python3
PYTHON=${ANSIBLE_TEST_PYTHON_INTERPRETER:-python}

# Run full test suite
virtualenv --system-site-packages --python "${PYTHON}" "${MYTMPDIR}/botocore-recent"
source "${MYTMPDIR}/botocore-recent/bin/activate"
$PYTHON -m pip install 'botocore>=1.10.1' boto3

run_test "EKS build up" playbooks/eks.yml -i ../../inventory -e @../../integration_config.yml -e @../../cloud-config-aws.yml -v "$@"
#run_test "Test EKS works" playbooks/test.yml -i ../../inventory -e @../../integration_config.yml -e @../../cloud-config-aws.yml -v "$@"
#run_test "Corrupt EKS state" playbooks/corrupt.yml -i ../../inventory -e @../../integration_config.yml -e @../../cloud-config-aws.yml -v "$@"
#run_test "Validate EKS state" playbooks/validate.yml --validate-state -i ../../inventory -e @../../integration_config.yml -e @../../cloud-config-aws.yml -v "$@"
#run_test "Enforce EKS state" playbooks/eks.yml --enforce-state -i ../../inventory -e @../../integration_config.yml -e @../../cloud-config-aws.yml -v "$@"
run_test "EKS tear down" playbooks/eks.yml --state absent -i ../../inventory -e @../../integration_config.yml -e @../../cloud-config-aws.yml -v "$@"
