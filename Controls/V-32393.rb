# encoding: UTF-8

control "V-32393" do
  title "The audit information produced by the DBMS must be protected from
unauthorized read access."
  desc  "If audit data were to become compromised, then competent forensic
analysis and discovery of the true source of potentially malicious system
activity is difficult, if not impossible, to achieve. In addition, access to
audit records provides information an attacker could potentially use to his or
her advantage.

    To ensure the veracity of audit data, the information system and/or the
application must protect audit information from any and all unauthorized
access. This includes read, write, copy, etc.

    This requirement can be achieved through multiple methods which will depend
upon system architecture and design. Some commonly employed methods include
ensuring log files enjoy the proper file system permissions utilizing file
system protections and limiting log data location.

    Additionally, applications with user interfaces to audit records should not
allow for the unfettered manipulation of or access to those records via the
application. If the application provides access to the audit data, the
application becomes accountable for ensuring that audit information is
protected from unauthorized access.

    Audit information includes all information (e.g., audit records, audit
settings, and audit reports) needed to successfully audit information system
activity.
  "
  desc  "check", "
    Review the access permissions to tools used to view or modify audit
information produced by CouchDB. These tools may include features within
CouchDB itself or software external to the database.

    The file path to audit information produced by CouchDB is defined in the
default.ini configuration file. Only authorized users should have permission to
access this information.

    Verify the permission of the log files produced by CouchDB with the
following commands:

      # find . -name \"default.ini\"
      # grep \"file =\" <path to default.ini>
      # ls -la <path of .ini file>

    If the audit information produced by CouchDB is not protected from
unauthorized read access, this is a finding.
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
  tag "gtitle": "SRG-APP-000118-DB-000059"
  tag "gid": "V-32393"
  tag "rid": "SV-42730r3_rule"
  tag "stig_id": "SRG-APP-000118-DB-000059"
  tag "fix_id": nil
  tag "cci": ["CCI-000162"]
  tag "nist": ["AU-9", "Rev_4"]
  
 describe command('ls -la default.ini') do
  it { should exist }
  its('stdout') { should eq 'authorized_users' }
end
end

