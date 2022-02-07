# encoding: UTF-8

control "V-58089" do
  title "The DBMS must generate audit records when unsuccessful attempts to
modify security objects occur."
  desc  "Changes in the database objects (tables, views, procedures, functions)
that record and control permissions, privileges, and roles granted to users and
roles must be tracked. Without an audit trail, unauthorized changes to the
security subsystem could go undetected. The database could be severely
compromised or rendered inoperative.

    To aid in diagnosis, it is necessary to keep track of failed attempts in
addition to the successful ones.
  "
  desc  "check", "
    Review the CouchDB database documentation and deployed configuration to
verify that the database is configured to log audit records for when
unsuccessful attempts to modify security objects occur.

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to log  when unsuccessful attempts to modify security
objects occur, this is a finding.
  "
  desc  "fix", "
    Configure CouchDB to generate audit records when unsuccessful attempts to
modify security objects occur.

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000496-DB-000335"
  tag "gid": "V-58089"
  tag "rid": "SV-72519r1_rule"
  tag "stig_id": "SRG-APP-000496-DB-000335"
  tag "fix_id": nil
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
  
  describe ini(input('couchdb_conf_default')) do
    its('log.level') { should eq 'info' }
  end
end

