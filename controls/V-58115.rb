# encoding: UTF-8

control "V-58115" do
  title "The DBMS must generate audit records for all privileged activities or
other system-level access."
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

    There may also be Data Manipulation Language (DML) statements that, subject
to context, should be regarded as privileged. Possible examples in SQL include:

    TRUNCATE TABLE;
    DELETE, or
    DELETE affecting more than n rows, for some n, or
    DELETE without a WHERE clause;

    UPDATE or
    UPDATE affecting more than n rows, for some n, or
    UPDATE without a WHERE clause;

    any SELECT, INSERT, UPDATE, or DELETE to an application-defined security
table executed by other than a security principal.

    Depending on the capabilities of the DBMS and the design of the database
and associated applications, audit logging may be achieved by means of DBMS
auditing features, database triggers, other mechanisms, or a combination of
these.

    Note that it is particularly important to audit, and tightly control, any
action that weakens the implementation of this requirement itself, since the
objective is to have a complete audit trail of all administrative activity.
  "
  desc  "check", "
    Review the CouchDB database documentation and deployed configuration to
verify that the database is configured to log audit records for all privileged
activities or other system-level access.

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.

    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to log audit records for all privileged activities or
other system-level access, this is a finding.
  "
  desc  "fix", "
    Configure CouchDB to generate audit records for all privileged activities
or other system-level access.

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000504-DB-000354"
  tag "gid": "V-58115"
  tag "rid": "SV-72545r1_rule"
  tag "stig_id": "SRG-APP-000504-DB-000354"
  tag "fix_id": nil
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
  
  describe ini(input('couchdb_conf_defaultt')) do
    its('log.level') { should eq 'info' }
  end
end

