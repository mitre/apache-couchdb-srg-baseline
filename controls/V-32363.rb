# encoding: UTF-8

control "V-32363" do
  title "The DBMS must allow only the ISSM (or individuals or roles appointed
by the ISSM) to select which auditable events are to be audited."
  desc  "check", "
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
  desc  "fix", "
As the system administrator, change the permissions of the configuration files:

  # sudo chown -R <Database Admin>:<Database Admin Group> <Configuration file>
  # sudo chmod 600 <Configuration file>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000090-DB-000065"
  tag "gid": "V-32363"
  tag "rid": "SV-42700r3_rule"
  tag "stig_id": "SRG-APP-000090-DB-000065"
  tag "fix_id": nil
  tag "cci": ["CCI-000171"]
  tag "nist": ["AU-12 b", "Rev_4"]

  
  if file(input('couchdb_conf_default')).exist?
    describe file(input('couchdb_conf_default')) do
      its ('mode') { should be 0640 }
      its ('owner') { should eq input('couchdb_owner') }
    end
  else
    describe "The #{input('couchdb_conf_default')} file is missing, we cannot test this control" do
    skip "The input('couchdb_conf_default') file is missing, please restore the file and rerun the test"
    end
  end
end

