# encoding: UTF-8

control 'V-58075' do
  title "The DBMS must generate audit records when privileges/permissions are
modified."
  desc  "Changes in the permissions, privileges, and roles granted to users and
roles must be tracked. Without an audit trail, unauthorized elevation or
restriction of privileges could go undetected. Elevated privileges give users
access to information and functionality that they should not have; restricted
privileges wrongly deny access to authorized users.

    In an SQL environment, modifying permissions is typically done via the
GRANT, REVOKE, and DENY commands.
  "
  desc  'check', "
    Review the CouchDB documentation to verify that audit records can be
produced  when privileges/permissions are modified.
    # find . -name \"default.ini\"

    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to log audit records when privileges/permissions are
modified, this is a finding.
  "
  desc  'fix', "
    Configure CouchDB to set to log audit records when privileges/permissions
are modified.

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000495-DB-000328"
  tag gid: "V-58075"
  tag rid: "SV-72505r2_rule"
  tag stig_id: "SRG-APP-000495-DB-000328"
  tag fix_id: nil
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c", "Rev_4"]
end

