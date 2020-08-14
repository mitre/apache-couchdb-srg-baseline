# encoding: UTF-8

control "V-32394" do
  title "The audit information produced by the DBMS must be protected from
unauthorized modification."
  desc  "If audit data were to become compromised, then competent forensic
analysis and discovery of the true source of potentially malicious system
activity is impossible to achieve.

    To ensure the veracity of audit data the information system and/or the
application must protect audit information from unauthorized modification.

    This requirement can be achieved through multiple methods that will depend
upon system architecture and design. Some commonly employed methods include
ensuring log files enjoy the proper file system permissions and limiting log
data locations.

    Applications providing a user interface to audit data will leverage user
permissions and roles identifying the user accessing the data and the
corresponding rights that the user enjoys in order to make access decisions
regarding the modification of audit data.

    Audit information includes all information (e.g., audit records, audit
settings, and audit reports) needed to successfully audit information system
activity.

    Modification of database audit data could mask the theft of, or the
unauthorized modification of, sensitive data stored in the database.
  "
  desc  "check", "
    Review the access permissions to tools used to view or modify audit
information produced by CouchDB. These tools may include features within
CouchDB itself or software external to the database.

    The file path to audit information produced by CouchDB is defined in the
default.ini configuration file. Only authorized users should have permission to
modify this information.

    Verify the permission of the log files produced by CouchDB with the
following commands:

      # find . -name \"default.ini\"
      # grep \"file =\" <path to default.ini>
      # ls -la <path of .ini file>

    If the audit information produced by CouchDB is not protected from
unauthorized modification, this is a finding.
  "
  desc  "fix", "
    As the system administrator, change the permissions of the configuration
files:

      # find . -name \"default.ini\"
      # grep \"file =\" <path to default.ini>
      # sudo chown -R <Database Admin>:<Database Admin Group> <Log File>
      # sudo chmod 600 <Log File>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000119-DB-000060"
  tag "gid": "V-32394"
  tag "rid": "SV-42731r3_rule"
  tag "stig_id": "SRG-APP-000119-DB-000060"
  tag "fix_id": nil
  tag "cci": ["CCI-000163"]
  tag "nist": ["AU-9", "Rev_4"]
  
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

