control 'SV-230279' do
  title 'RHEL 8 must clear SLUB/SLAB objects to prevent use-after-free attacks.'
  desc 'Some adversaries launch attacks with the intent of executing code in nonexecutable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can be either hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Poisoning writes an arbitrary value to freed pages, so any modification or reference to that page after being freed or before being initialized will be detected and prevented. This prevents many types of use-after-free vulnerabilities at little performance cost. Also prevents leak of data and detection of corrupted memory.

SLAB objects are blocks of physically-contiguous memory.  SLUB is the unqueued SLAB allocator.'
  desc 'check', 'Verify that GRUB2 is configured to mitigate use-after-free vulnerabilities by employing memory poisoning.

Inspect the "GRUB_CMDLINE_LINUX" entry of /etc/default/grub as follows:

$ sudo grep -i grub_cmdline_linux /etc/default/grub

GRUB_CMDLINE_LINUX="... init_on_free=1"

If "init_on_free=1" is missing or commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to enable poisoning of SLUB/SLAB objects with the
following commands:

    $ sudo grubby --update-kernel=ALL --args="slub_debug=P"

    Add or modify the following line in "/etc/default/grub" to ensure the
configuration survives kernel updates:

    GRUB_CMDLINE_LINUX="slub_debug=P"'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag satisfies: ['SRG-OS-000134-GPOS-00068', 'SRG-OS-000433-GPOS-00192']
  tag gid: 'V-230279'
  tag rid: 'SV-230279r1069286_rule'
  tag stig_id: 'RHEL-08-010423'
  tag fix_id: 'F-32923r1069180_fix'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe 'GRUB config' do
    it 'should enable memory poisoning via init_on_free=1' do
      expect(parse_config_file('/etc/default/grub')['GRUB_CMDLINE_LINUX']).to match(/init_on_free\s*=\s*1/),
        'init_on_free=1 not found in GRUB_CMDLINE_LINUX in /etc/default/grub'
    end
  end
end
