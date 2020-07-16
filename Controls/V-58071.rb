# encoding: UTF-8

control 'V-58071' do
  title "The DBMS must generate audit records when privileges/permissions are
added."
  desc  "Changes in the permissions, privileges, and roles granted to users and
roles must be tracked. Without an audit trail, unauthorized elevation or
restriction of privileges could go undetected. Elevated privileges give users
access to information and functionality that they should not have; restricted
privileges wrongly deny access to authorized users.

    In an SQL environment, adding permissions is typically done via the GRANT
command, or, in the negative, the DENY command.
  "
  desc  'check', "
    Review the CouchDB documentation to verify that audit records can be
produced when privileges/permissions/role memberships are added.
    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"level =\" <path to default.ini>

    if line does not exist or is not set to info, this is a finding.

    If it is not set to log audit records when privileges/ permissions are
added, this is a finding.
  "
  desc  'fix', "
    Configure CouchDB to set to log audit records when privileges/ permissions
are added.

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000495-DB-000326'
  tag gid: 'V-58071'
  tag rid: 'SV-72501r2_rule'
  tag stig_id: 'SRG-APP-000495-DB-000326'
  tag fix_id: nil
  tag ccii: CCI-000172
  tag nist: 'AU-12 c'
end

