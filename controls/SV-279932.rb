control 'SV-279932' do
  title 'RHEL 8 cryptographic policy must not be overridden.'
  desc 'Centralized cryptographic policies simplify applying secure ciphers
across an operating system and the applications that run on that operating
system. Use of weak or untested encryption algorithms undermines the purposes
of utilizing encryption to protect data.'
  desc 'check', 'Verify RHEL 8 cryptographic policies are not overridden.

Verify the configured policy matches the generated policy with the following command:

$ sudo update-crypto-policies --is-applied

The configured policy is applied

If the returned message does not match the above, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to correctly implement the systemwide cryptographic policies by reinstalling the crypto-policies package contents.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag gid: 'V-279932'
  tag rid: 'SV-279932r1156349_rule'
  tag stig_id: 'RHEL-08-010270'
  tag fix_id: 'F-84397r1156348_fix'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13']
  tag 'host'
  tag 'container'

  only_if('crypto-policies package is not installed - Not Applicable', impact: 0.0) {
    package('crypto-policies').installed?
  }

  describe command('update-crypto-policies --is-applied') do
    its('stdout.strip') { should cmp 'The configured policy is applied' }
  end
end
