# encoding: UTF-8

control 'V-58121' do
  title "The DBMS must generate audit records when unsuccessful accesses to
objects occur."
  desc  "Without tracking all or selected types of access to all or selected
objects (tables, views, procedures, functions, etc.), it would be difficult to
establish, correlate, and investigate the events relating to an incident or
identify those responsible for one.

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
verify that the database is configured to log audit records for when
unsuccessful accesses to objects occur.

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.

    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to log when unsuccessful accesses to objects occur, this
is a finding.
  "
  desc  'fix', "
    Configure CouchDB to enerate audit records when unsuccessful accesses to
objects occur.

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000507-DB-000357'
  tag gid: 'V-58121'
  tag rid: 'SV-72551r1_rule'
  tag stig_id: 'SRG-APP-000507-DB-000357'
  tag fix_id: nil
  tag ccii: CCI-000172
  tag nist: 'AU-12 c'
end

