control 'SV-272483' do
  title 'The RHEL 8 SSH client must be configured to use only DOD-approved
encryption ciphers employing FIPS 140-3-validated cryptographic hash algorithms
to protect the confidentiality of SSH client connections.'
  desc 'Without cryptographic integrity protections, information can be
altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an
authorized user (or an information system) communicating through an external,
nonorganization-controlled network. Remote access methods include, for example,
dial-up, broadband, and wireless.

RHEL 8 incorporates systemwide crypto policies by default. The SSH
configuration file has no effect on the ciphers, MACs, or algorithms unless
specifically defined in the /etc/sysconfig/sshd file. The employed algorithms
can be viewed in the /etc/crypto-policies/back-ends/openssh.config file.'
  desc 'check', 'Verify the RHEL 8 SSH client is configured to use only ciphers employing FIPS 140-3 approved algorithms.

To verify the ciphers in the systemwide SSH configuration file, use the following command:

$ grep -i Ciphers /etc/crypto-policies/back-ends/openssh.config

Ciphers aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr

If the cipher entries in the "openssh.config" file have any ciphers other than "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr", the order differs from the example above, or they are missing or commented out, this is a finding.'
  desc 'fix', 'Configure the RHEL 8 SSH client to use only ciphers employing FIPS 140-3 approved algorithms.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag gid: 'V-272483'
  tag rid: 'SV-272483r1184243_rule'
  tag stig_id: 'RHEL-08-010297'
  tag fix_id: 'F-76443r1155360_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
  tag 'host'
  tag 'container-conditional'

  openssh_config = '/etc/crypto-policies/back-ends/openssh.config'

  only_if('This control is Not Applicable to containers without crypto-policies openssh config', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file(openssh_config).exist?)
  }

  approved_ciphers = input('openssh_client_required_ciphers')

  if file(openssh_config).exist?
    cipher_line = command("grep -i Ciphers #{openssh_config}").stdout.strip

    describe 'SSH client Ciphers configuration' do
      subject { cipher_line }
      it { should_not be_empty }
    end

    actual_ciphers = cipher_line.gsub(/.*Ciphers\s*=?\s*/, '').split(',').map(&:strip)
    describe 'SSH client Ciphers' do
      it 'should only contain FIPS 140-3 approved algorithms' do
        unapproved = actual_ciphers - approved_ciphers
        expect(unapproved).to be_empty,
          "Unapproved ciphers found: #{unapproved.join(', ')}"
      end
    end
  end
end
