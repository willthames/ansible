#!/bin/sh

MYTMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'mytmpdir')

# Run tests
ansible-playbook playbooks/state-test.yml -e tempdir=$MYTMPDIR -v --state absent $@ && \
  ansible-playbook playbooks/state-test.yml -e tempdir=$MYTMPDIR -v $@ && \
  ansible-playbook playbooks/corrupt-state.yml -e tempdir=$MYTMPDIR -v $@ && \
  ansible-playbook playbooks/validate-state.yml -e tempdir=$MYTMPDIR -v --validate-state $@ && \
  ansible-playbook playbooks/state-test.yml -e tempdir=$MYTMPDIR -v --enforce-state $@

# Clean up
ansible-playbook playbooks/state-test.yml -v -e tempdir=$MYTMPDIR --state absent $@
