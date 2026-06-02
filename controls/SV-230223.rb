control 'SV-230223' do
  title 'RHEL 8 must implement NIST FIPS-validated cryptography for the following: To provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

RHEL 8 utilizes GRUB 2 as the default bootloader. Note that GRUB 2 command-line parameters are defined in the "kernelopts" variable of the /boot/grub2/grubenv file for all kernel boot entries. The command "fips-mode-setup" modifies the "kernelopts" variable, which in turn updates all kernel boot entries.

The fips=1 kernel option needs to be added to the kernel command line during system installation so that key generation is done with FIPS-approved algorithms and continuous monitoring tests in place. Users must also ensure the system has plenty of entropy during the installation process by moving the mouse around, or if no mouse is available, ensuring that many keystrokes are typed. The recommended amount of keystrokes is 256 and more. Less than 256 keystrokes may generate a nonunique key.'
  desc 'check', 'Verify RHEL 8 is set to use a FIPS 140-3-compliant systemwide cryptographic policy with the following command:

     $ sudo update-crypto-policies --show
     FIPS:STIG

If the systemwide crypto policy is not set to "FIPS", this is a finding.

Verify the current minimum crypto-policy configuration with the following commands:

     $ sudo grep -E \'rsa_size|hash\' /etc/crypto-policies/state/CURRENT.pol
     hash = SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512
     min_rsa_size = 2048

If the "hash" values do not include at least SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512, this is a finding.
If there are algorithms that include "SHA1" or a hash value less than "224", this is a finding.
If the "min_rsa_size" is not set to at least "2048", this is a finding.
If these commands do not return any output, this is a finding.'
  desc 'fix', 'Configure the operating system to implement DOD-approved encryption by following the steps below:

To enable strict FIPS compliance, the fips=1 kernel option needs to be added to the kernel boot parameters during system installation so key generation is done with FIPS-approved algorithms and continuous monitoring tests in place.

Enable FIPS mode after installation (not strict FIPS-compliant) with the following command:

     $ sudo fips-mode-setup --enable

Reboot the system for the changes to take effect.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000396-GPOS-00176', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000478-GPOS-00223']
  tag gid: 'V-230223'
  tag rid: 'SV-230223r1155356_rule'
  tag stig_id: 'RHEL-08-010020'
  tag fix_id: 'F-32867r1155355_fix'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable in a container' do
      skip 'The host OS controls the FIPS mode settings. The host OS should also be scanned with the applicable OS validation profile.'
    end
  elsif input('use_fips') == false
    impact 0.0
    describe 'This control is Not Applicable as FIPS is not required for this system' do
      skip 'This control is Not Applicable as FIPS is not required for this system'
    end
  else
    describe command('update-crypto-policies --show') do
      its('stdout.strip') { should match(/^FIPS/) }
    end

    required_hashes = %w[SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512]
    hash_line = command("grep -E '^hash' /etc/crypto-policies/state/CURRENT.pol").stdout.strip

    describe 'Crypto policy hash algorithms' do
      it 'should include all required FIPS 140-3-compliant algorithms and exclude weak ones' do
        expect(hash_line).not_to be_empty, '/etc/crypto-policies/state/CURRENT.pol missing hash configuration'
        hashes = hash_line.gsub(/^hash\s*=\s*/, '').split
        required_hashes.each do |h|
          expect(hashes).to include(h), "Required hash algorithm #{h} not found in crypto policy"
        end
        bad = hashes.select { |h| h.match?(/SHA1/) }
        expect(bad).to be_empty, "Non-compliant hash algorithms found: #{bad.join(', ')}"
      end
    end

    rsa_line = command("grep 'min_rsa_size' /etc/crypto-policies/state/CURRENT.pol").stdout.strip
    describe 'Crypto policy min_rsa_size' do
      it 'should be at least 2048' do
        expect(rsa_line).not_to be_empty, '/etc/crypto-policies/state/CURRENT.pol missing min_rsa_size configuration'
        rsa_size = rsa_line.match(/min_rsa_size\s*=\s*(\d+)/)&.captures&.first.to_i
        expect(rsa_size).to be >= 2048, "min_rsa_size is #{rsa_size}, expected >= 2048"
      end
    end
  end
end
