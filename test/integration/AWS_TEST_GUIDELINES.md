# Guidelines for writing test cases for Amazon Web Services in Ansible.

Ansible integration test cases are simply normal playbooks that are
executed and include verification.  The AWS tests are all run as roles
within the top level `amazon.yml` file.  

### Support Roles

When writing integration test cases for AWS you SHOULD use the
following support roles as includes within your meta directory


 * prepare_tests - this role is for general setup designed to be
   shared by all integration tests.

 * prepare_aws_tests - this is for inclusion in other roles as a dependency.  
   It checks that the environment is empty apart from the profile.

 * test_aws_noenv - all tests which require there to be no environment
   should be run here.  
 
 * setup_ec2 - This prepares ssh keys and other things useful for
   tests involving EC2 instances such as the load balancer tests.


### Expected Environment and Configuration


When the playbook is run, one environemnt variabe, AWS_PROFILE should
be set to:

   AWS_PROFILE=ansible-integration-testing

All other environment variables which deliver credentials should be
unset.  This can be verified by ensuring that every testing role
includes the setup

The user should configure that profile as normal with the details of
the account that they want to be accessed.

Some of the EC2 test cases rely on images which are only available in
us-east-1 this means that integration testing should be run in that
region in most cases.  Future test cases should be written so that
they run in any region.

If you want to make a test case that fails to connect to AWS, then you
can do this by manipulating the environment of your test case


- name: test fail to create key with missing credentials ec2_key:
  name='{{ec2_key_name}}' key_material='{{key_material}}'
  state=present environment: AWS_PROFILE:
  ansible-testing-fail-do-not-create register: result


- name: test fail to create key with missing credentials ec2_key:
  name='{{ec2_key_name}}' key_material='{{key_material}}'
  state=present environment: AWS_PROFILE:
  ansible-testing-fail-do-not-create register: result

Since ansible is unable to unset environment variables, test cases
which require AWS_PROFILE to be unset have to be done in a completely
separate role.  The main use for this is checking error messages in
the case where configution is missing.  For checks 


### Resource Naming and Tagging


Where possible all resources should be named with a name which starts
with the {{resource_prefix}} variable.   

- name: ensure launch config exists
  ec2_lc:
    name: "{{ resource_prefix }}-lc"
    ec2_access_key: "{{ ec2_access_key }}"
    ec2_secret_key: "{{ ec2_secret_key }}"
    region: "{{ ec2_region }}"
    image_id: ami-964a0efe
    instance_type: t2.micro

Where this is not possible and tagging is possible then the ressource
should be tagged with the resource prefix instead.

Where this is not possible please add a note to the README.md file
explicitly mentioning that the resource may be left over.