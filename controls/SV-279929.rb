control 'SV-279929' do
  title 'RHEL 8 must automatically exit interactive command shell user sessions after 10 minutes of inactivity.'
  desc 'Terminating an idle interactive command shell user session within a
short time period reduces the window of opportunity for unauthorized personnel
to take control of it when left unattended in a virtual terminal or at a
console.'
  desc 'check', 'Verify RHEL 8 is configured to exit interactive command shell user sessions after 10 minutes of inactivity or less with the following command:

$ sudo grep -i tmout /etc/profile /etc/profile.d/*.sh

/etc/profile.d/tmout.sh:declare -xr TMOUT=600

If "TMOUT" is not set to "600" or less in a script located in the "/etc/profile.d/" directory, is missing or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to exit interactive command shell user sessions after 10 minutes of inactivity.

Add or edit the following line in "/etc/profile.d/tmout.sh":

#!/bin/bash

declare -xr TMOUT=600'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag gid: 'V-279929'
  tag rid: 'SV-279929r1156340_rule'
  tag stig_id: 'RHEL-08-020360'
  tag fix_id: 'F-84394r1156339_fix'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  tmout_value = input('system_activity_timeout')

  tmout_found = command('grep -rh TMOUT /etc/profile /etc/profile.d/*.sh 2>/dev/null').stdout

  describe 'TMOUT configuration' do
    subject { tmout_found }
    it { should match(/TMOUT=\d+/) }
  end

  tmout_settings = tmout_found.scan(/TMOUT=(\d+)/).flatten.map(&:to_i)

  unless tmout_settings.empty?
    describe "Smallest TMOUT value (#{tmout_settings.min})" do
      it "should be #{tmout_value} seconds or less" do
        expect(tmout_settings.min).to be <= tmout_value
      end
    end
  end
end
