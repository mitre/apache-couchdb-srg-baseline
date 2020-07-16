# encoding: UTF-8

control 'V-58073' do
  title "The DBMS must generate audit records when unsuccessful attempts to add
privileges/permissions occur."
  desc  "Failed attempts to change the permissions, privileges, and roles
granted to users and roles must be tracked. Without an audit trail,
unauthorized attempts to elevate or restrict privileges could go undetected.

    In an SQL environment, adding permissions is typically done via the GRANT
command, or, in the negative, the DENY command.

    To aid in diagnosis, it is necessary to keep track of failed attempts in
addition to the successful ones.
  "
  desc  'check', "
    Review the CouchDB documentation to verify that audit records can be
produced  when unsuccessful attempts to add privileges/permissions occur.
    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.

    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to log audit records  when unsuccessful attempts to add
privileges/permissions occur, this is a finding.
  "
  desc  'fix', "
    Configure CouchDB to set to log audit records  when unsuccessful attempts
to add privileges/permissions occur.

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000495-DB-000327"
  tag gid: "V-58073"
  tag rid: "SV-72503r2_rule"
  tag stig_id: "SRG-APP-000495-DB-000327"
  tag fix_id: nil
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]
end

