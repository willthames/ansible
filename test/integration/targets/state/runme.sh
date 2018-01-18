#!/bin/sh

MYTMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'mytmpdir')

function run_test() {
  name=$1
  shift
  echo "**** RUNNING $name ****"
  echo ansible-playbook -e tempdir=$MYTMPDIR -v $@
  ansible-playbook -e tempdir=$MYTMPDIR -v $@
  rc=$?
  echo $rc
  return $rc
}

# Run tests
run_test "Clean up before tests" playbooks/state-test.yml --state absent $@ && \
run_test "Making things present" playbooks/state-test.yml $@ && \
run_test "Checking it twice" playbooks/state-test.yml $@ && \
run_test "Corrupt state" playbooks/corrupt-state.yml $@ && \
run_test "Validate state" playbooks/validate-state.yml --validate-state $@ && \
run_test "Enforce state" playbooks/state-test.yml --enforce-state $@

# Clean up
run_test "Clean up after tests" playbooks/state-test.yml --state absent $@
