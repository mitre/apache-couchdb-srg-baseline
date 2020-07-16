# encoding: UTF-8

control 'V-58087' do
  title "The DBMS must generate audit records when security objects are
modified."
  desc  "Changes in the database objects (tables, views, procedures, functions)
that record and control permissions, privileges, and roles granted to users and
roles must be tracked. Without an audit trail, unauthorized changes to the
security subsystem could go undetected. The database could be severely
compromised or rendered inoperative."
  desc  'check', "
    Review the CouchDB database documentation and deployed configuration to
verify that the database is configured to log audit records for when security
objects are modified.

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.

    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to log when security objects are modified, this is a
finding.
  "
  desc  'fix', "
    Configure CouchDB to generate audit records when security objects are
modified.

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000496-DB-000334'
  tag gid: 'V-58087'
  tag rid: 'SV-72517r1_rule'
  tag stig_id: 'SRG-APP-000496-DB-000334'
  tag fix_id: nil
  tag ccii: CCI-000172
  tag nist: 'AU-12 c'
end

