#!/bin/sh

MYTMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'mytmpdir')

function run_test() {
  name=$1
  shift
  echo "**** RUNNING $name ****"
  cmd="ansible-playbook -e tempdir=$MYTMPDIR -v $@"
  echo $cmd
  ANSIBLE_KEEP_REMOTE_FILES=1 ANSIBLE_STATE_FILE=$(basename $(dirname $MYTMPDIR)) $cmd
  rc=$?
  echo $rc
  return $rc
}

# Run tests
# Note state=absent variable is not required for strategy: state - it's used by a linear
# playbook to validate that the roles actually work
run_test "Clean up before tests" playbooks/state-test.yml --state absent -e state=absent $@ && \
run_test "Making things present" playbooks/state-test.yml $@ && \
run_test "Checking it twice" playbooks/state-test.yml $@ && \
run_test "Corrupt state" playbooks/corrupt-state.yml $@ && \
run_test "Validate state" playbooks/validate-state.yml --validate-state $@ && \
run_test "Enforce state" playbooks/state-test.yml --enforce-state $@

# Clean up
#run_test "Clean up after tests" playbooks/state-test.yml --state absent -e state=absent $@
