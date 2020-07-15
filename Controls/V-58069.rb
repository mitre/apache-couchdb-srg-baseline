# encoding: UTF-8

control 'V-58069' do
  title "The DBMS must be able to generate audit records when unsuccessful
attempts to retrieve privileges/permissions occur."
  desc  "Under some circumstances, it may be useful to monitor who/what is
reading privilege/permission/role information. Therefore, it must be possible
to configure auditing to do this. DBMSs typically make such information
available through views or functions.

    This requirement addresses explicit requests for privilege/permission/role
membership information. It does not refer to the implicit retrieval of
privileges/permissions/role memberships that the DBMS continually performs to
determine if any and every action on the database is permitted.

    To aid in diagnosis, it is necessary to keep track of failed attempts in
addition to the successful ones.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the CouchDB documentation to verify that audit records can be
produced when unsuccessful attempts to retrieve privileges/permissions occur.
    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.

    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to log audit records  when unsuccessful attempts to
retrieve privileges/permissions occur, this is a finding.
  "
  desc  'fix', "
    Configure CouchDB to set to log audit records when unsuccessful attempts to
retrieve privileges/permissions occur.

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000091-DB-000325'
  tag gid: 'V-58069'
  tag rid: 'SV-72499r1_rule'
  tag stig_id: 'SRG-APP-000091-DB-000325'
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

