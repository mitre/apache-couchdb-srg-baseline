# encoding: UTF-8

control 'V-58081' do
  title "The DBMS must generate audit records when unsuccessful attempts to
delete privileges/permissions occur."
  desc  "Failed attempts to change the permissions, privileges, and roles
granted to users and roles must be tracked. Without an audit trail,
unauthorized attempts to elevate or restrict privileges could go undetected.

    In an SQL environment, deleting permissions is typically done via the
REVOKE or DENY command.

    To aid in diagnosis, it is necessary to keep track of failed attempts in
addition to the successful ones.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the CouchDB documentation to verify that audit records can be
produced when unsuccessful attempts to delete privileges/permissions occur.
    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.

    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to log audit records when unsuccessful attempts to delete
privileges/permissions occur.
  "
  desc  'fix', "
    Configure CouchDB to set to log audit records when unsuccessful attempts to
delete privileges/permissions occur.

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000499-DB-000331'
  tag gid: 'V-58081'
  tag rid: 'SV-72511r2_rule'
  tag stig_id: 'SRG-APP-000499-DB-000331'
  tag fix_id: nil
  tag cci: "CCI-000172
The information system generates audit records for the events defined in AU-2 d
with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c

"
  tag nist: 'AU-12 c'
end

