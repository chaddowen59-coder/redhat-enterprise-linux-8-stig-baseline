control 'SV-279930' do
  title 'RHEL 8 IP tunnels must use FIPS 140-3-approved cryptographic algorithms.'
  desc 'Overriding the system crypto policy makes the behavior of the Libreswan
service violate expectations and makes system configuration more fragmented.'
  desc 'check', 'Note: If the IPsec service is not installed, this is not applicable.

Verify the IPsec service uses the system crypto policy with the following command:

$ sudo grep include /etc/ipsec.conf /etc/ipsec.d/*.conf

/etc/ipsec.conf:include /etc/crypto-policies/back-ends/libreswan.config
/etc/ipsec.conf:include /etc/ipsec.d/*.conf

If the ipsec configuration file does not contain "include /etc/crypto-policies/back-ends/libreswan.config", this is a finding.'
  desc 'fix', 'Configure Libreswan to use the system cryptographic policy.

Add the following line to "/etc/ipsec.conf":

include /etc/crypto-policies/back-ends/libreswan.config'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag gid: 'V-279930'
  tag rid: 'SV-279930r1184239_rule'
  tag stig_id: 'RHEL-08-010280'
  tag fix_id: 'F-84395r1156342_fix'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  only_if('IPsec service (libreswan) is not installed - Not Applicable', impact: 0.0) {
    package('libreswan').installed?
  }

  describe file('/etc/ipsec.conf') do
    it { should exist }
    its('content') { should match(%r{include\s+/etc/crypto-policies/back-ends/libreswan\.config}) }
  end
end
