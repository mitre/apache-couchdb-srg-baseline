# encoding: UTF-8

control 'V-32363' do
  title "The DBMS must allow only the ISSM (or individuals or roles appointed
by the ISSM) to select which auditable events are to be audited."
  desc  'rationale', ''
  desc  'check', "
    Review the access permissions to tools used to view or modify audit log
configurations. These tools may include features within CouchDB itself or
software external to the database.

    Logging configuration is defined in the default.ini configuration file and
other .ini files. Only ISSM (or individuals or roles appointed by the ISSM)
should have permission to write to the file.

    Verify the permission of the .ini files with the following commands:

      # find . -name \"*.ini\"
      # ls -la <path of .ini file>

    If any of these .ini files give write permissions to any user other than
ISSM (or individuals or roles appointed by the ISSM), this is a finding.
  "
  desc  'fix', "
    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag gid: 'V-32363'
  tag rid: 'SV-42700r3_rule'
  tag stig_id: 'SRG-APP-000090-DB-000065'
  tag fix_id: nil
  tag cci: "CCI-000171
The information system allows organization-defined personnel or roles to select
which auditable events are to be audited by specific components of the
information system.
NIST SP 800-53 :: AU-12 b
NIST SP 800-53A :: AU-12.1 (iii)
NIST SP 800-53 Revision 4 :: AU-12 b

"
  tag nist: 'AU-12 b'
end

