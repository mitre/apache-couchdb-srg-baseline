# encoding: UTF-8

control 'V-32362' do
  desc  "Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    Audit records can be generated from various components within the DBMS
(e.g., process, module). Certain specific application functionalities may be
audited as well. The list of audited events is the set of events for which
audits are to be generated. This set of events is typically a subset of the
list of all events for which the system is capable of generating audit records.

    DoD has defined the list of events for which the DBMS will provide an audit
record generation capability as the following:

    (i) Successful and unsuccessful attempts to access, modify, or delete
privileges, security objects, security levels, or categories of information
(e.g., classification levels);

    (ii) Access actions, such as successful and unsuccessful logon attempts,
privileged activities, or other system-level access, starting and ending time
for user access to the system, concurrent logons from different workstations,
successful and unsuccessful accesses to objects, all program initiations, and
all direct access to the information system; and

    (iii) All account creation, modification, disabling, and termination
actions.

    Organizations may define additional events requiring continuous or ad hoc
auditing.
  "
  desc  'check', "
    Check CouchDB auditing to determine whether organization-defined auditable
events are being audited by the system.

    If organization-defined auditable events are not being audited, this is a
finding.

    The level of auditing configured can be found by running:
    # find . -name \"default.ini\"
    # grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.
  "
  desc  'fix', "
    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag gid: 'V-32362'
  tag rid: 'SV-42699r3_rule'
  tag stig_id: 'SRG-APP-000089-DB-000064'
  tag fix_id: nil
  tag ccii: CCI-000169
  tag nist: 'AU-12 a'
end

