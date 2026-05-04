control 'SV-274877' do
  title 'RHEL 8 must audit any script or executable called by cron as root or by any privileged user.'
  desc 'Any script or executable called by cron as root or by any privileged
user must be owned by that user, must have the permissions set to 755 or more
restrictive, and have no extended rights that allow any user to modify the
content of the file.'
  desc 'check', 'Verify RHEL 8 is configured to audit the execution of any system call made by cron as root or as any privileged user.

$ sudo auditctl -l | grep /etc/cron.d
-w /etc/cron.d -p wa -k cronjobs

$ sudo auditctl -l | grep /var/spool/cron
-w /var/spool/cron -p wa -k cronjobs

If either of these commands do not return the expected output, or the lines are commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to audit the execution of any system call made by cron as root or as any privileged user.

Add or update the following file system rules to "/etc/audit/rules.d/audit.rules":
-w /etc/cron.d/ -p wa -k cronjobs
-w /var/spool/cron/ -p wa -k cronjobs

To load the rules to the kernel immediately, run the following command:

$ sudo augenrules --load'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag gid: 'V-274877'
  tag rid: 'SV-274877r1155381_rule'
  tag stig_id: 'RHEL-08-030655'
  tag fix_id: 'F-78883r1155380_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe auditd do
    its('lines') { should include %r{-w /etc/cron\.d/?} }
  end

  describe auditd do
    its('lines') { should include %r{-w /var/spool/cron/?} }
  end
end
