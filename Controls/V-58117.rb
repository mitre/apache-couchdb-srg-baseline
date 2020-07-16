# encoding: UTF-8

control 'V-58117' do
  title "The DBMS must generate audit records when unsuccessful attempts to
execute privileged activities or other system-level access occur."
  desc  "Without tracking privileged activity, it would be difficult to
establish, correlate, and investigate the events relating to an incident or
identify those responsible for one.

    System documentation should include a definition of the functionality
considered privileged.

    A privileged function in this context is any operation that modifies the
structure of the database, its built-in logic, or its security settings. This
would include all Data Definition Language (DDL) statements and all
security-related statements. In an SQL environment, it encompasses, but is not
necessarily limited to:
    CREATE
    ALTER
    DROP
    GRANT
    REVOKE
    DENY

    Note that it is particularly important to audit, and tightly control, any
action that weakens the implementation of this requirement itself, since the
objective is to have a complete audit trail of all administrative activity.

    To aid in diagnosis, it is necessary to keep track of failed attempts in
addition to the successful ones.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the CouchDB database documentation and deployed configuration to
verify that the database is configured to log audit records for unsuccessful
attempts to execute privileged activities or other system-level access occur.

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to log audit records for unsuccessful attempts to execute
privileged activities or other system-level access occur, this is a finding.
  "
  desc  'fix', "
    Configure CouchDB to generate audit records when unsuccessful attempts to
execute privileged activities or other system-level access occur.

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000504-DB-000355'
  tag gid: 'V-58117'
  tag rid: 'SV-72547r1_rule'
  tag stig_id: 'SRG-APP-000504-DB-000355'
  tag fix_id: nil
  tag ccii: CCI-000172
  tag nist: 'AU-12 c'
end

