control 'SV-279931' do
  title 'RHEL 8 must implement DOD-approved encryption in the bind package.'
  desc 'Without cryptographic integrity protections, information can be altered
by unauthorized users without detection.

Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography
enabling distribution of the public key to verify the hash information while
maintaining the confidentiality of the secret key used to generate the hash.'
  desc 'check', 'Note: If the "bind" package is not installed, this requirement is Not Applicable.

Verify BIND uses the system crypto policy with the following command:

$ sudo grep include /etc/named.conf

include "/etc/crypto-policies/back-ends/bind.config";

If BIND is installed and the BIND config file does not contain the include "/etc/crypto-policies/back-ends/bind.config" directive, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure BIND to use the system crypto policy.

Add the following line to the "options" section in "/etc/named.conf":

include "/etc/crypto-policies/back-ends/bind.config";'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag gid: 'V-279931'
  tag rid: 'SV-279931r1184237_rule'
  tag stig_id: 'RHEL-08-010275'
  tag fix_id: 'F-84396r1156345_fix'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable - bind package is not installed', impact: 0.0) {
    package('bind').installed?
  }

  describe file('/etc/named.conf') do
    it { should exist }
    its('content') { should match(%r{include\s+"/etc/crypto-policies/back-ends/bind\.config"}) }
  end
end
