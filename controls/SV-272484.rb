control 'SV-272484' do
  title 'RHEL 8 must elevate the SELinux context when an administrator calls the sudo command.'
  desc 'Preventing nonprivileged users from executing privileged functions
mitigates the risk that unauthorized individuals or processes may gain
unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing
system integrity checks, or administering cryptographic key management
activities. Nonprivileged users are individuals who do not possess appropriate
authorizations.'
  desc 'check', 'Verify the operating system elevates the SELinux context when an administrator calls the sudo command with the following command:

This command must be run as root:

# grep -r sysadm_r /etc/sudoers /etc/sudoers.d
/etc/sudoers.d/admins:<username> ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL

If conflicting results are returned, this is a finding.

If a designated sudoers administrator group or account(s) is not configured to elevate the SELinux type and role to "sysadm_t" and "sysadm_r" with the use of the sudo command, this is a finding.'
  desc 'fix', 'Configure the operating system to elevate the SELinux context when an administrator calls the sudo command.

Edit a file in the "/etc/sudoers.d" directory with the following command:

$ sudo visudo -f /etc/sudoers.d/<customfile>

Use the following example to build the <customfile> in the /etc/sudoers.d directory to allow any administrator belonging to a designated sudoers admin group to elevate their SELinux context with the use of sudo:

%<designated_admins_group> ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag gid: 'V-272484'
  tag rid: 'SV-272484r1134875_rule'
  tag stig_id: 'RHEL-08-010455'
  tag fix_id: 'F-76444r1134874_fix'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command('grep -r sysadm_r /etc/sudoers /etc/sudoers.d') do
    its('stdout') { should match(/sysadm_r/) }
  end
end
