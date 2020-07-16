# encoding: UTF-8

control 'V-58085' do
  title "The DBMS must generate audit records when unsuccessful attempts to
access security objects occur."
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

    To aid in diagnosis, it is necessary to keep track of failed attempts in
addition to the successful ones.
  "
  desc  'check', "
    Review the CouchDB database documentation and deployed configuration to
verify that the database is configured to log audit records forunsuccessful
attempts to access security objects occur.

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.

    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to log audit records for unsuccessful attempts to access
security objects occur., this is a finding.
  "
  desc  'fix', "
    Configure CouchDB to generate audit records when unsuccessful attempts to
access security objects occur.

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000492-DB-000333'
  tag gid: 'V-58085'
  tag rid: 'SV-72515r1_rule'
  tag stig_id: 'SRG-APP-000492-DB-000333'
  tag fix_id: nil
  tag ccii: CCI-000172
  tag nist: 'AU-12 c'
end

