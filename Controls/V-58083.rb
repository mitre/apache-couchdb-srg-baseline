# encoding: UTF-8

control 'V-58083' do
  title "The DBMS must be able to generate audit records when security objects
are accessed."
  desc  "Changes to the security configuration must be tracked.

    This requirement applies to situations where security data is retrieved or
modified via data manipulation operations, as opposed to via specialized
security functionality.

    In an SQL environment, types of access include, but are not necessarily
limited to:
    SELECT
    INSERT
    UPDATE
    DELETE
    EXECUTE
  "
  desc  'rationale', ''
  desc  'check', "
    Review the CouchDB documentation to verify that audit records can be
produced when security objects are accessed.
    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.

    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to log audit records when security objects are accessed,
this is a finding.
  "
  desc  'fix', "
    Configure CouchDB to set to log audit records when security objects are
accessed.

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000492-DB-000332'
  tag gid: 'V-58083'
  tag rid: 'SV-72513r1_rule'
  tag stig_id: 'SRG-APP-000492-DB-000332'
  tag fix_id: nil
  tag ccii: CCI-000172
  tag nist: 'AU-12 c'
end

