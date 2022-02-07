# encoding: UTF-8

control "V-58065" do
  title "The DBMS must generate time stamps, for audit records and application
data, with a minimum granularity of one second."
  desc  "Without sufficient granularity of time stamps, it is not possible to
adequately determine the chronological order of records.

    Time stamps generated by the DBMS must include date and time. Granularity
of time measurements refers to the precision available in time stamp values.
Granularity coarser than one second is not sufficient for audit trail purposes.
Time stamp values are typically presented with three or more decimal places of
seconds; however, the actual granularity may be coarser than the apparent
precision. For example, SQL Server's GETDATE()/CURRENT_TMESTAMP values are
presented to three decimal places, but the granularity is not one millisecond:
it is about 1/300 of a second.

    Some DBMS products offer a data type called TIMESTAMP that is not a
representation of date and time. Rather, it is a database state counter and
does not correspond to calendar and clock time. This requirement does not refer
to that meaning of TIMESTAMP.
  "
  desc  "check", "
    Review the CouchDB database documentation and deployed configuration to
verify that the database is configured to generate time stamps, for audit
records and application data, with a minimum granularity of one second.\t

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"writer = \" <path to default.ini>
    if line is equal to journald, this is a finding.

    If it is not set to generate time stamps, for audit records and application
data, with a minimum granularity of one second, this is a finding.
  "
  desc  "fix", "
    If applicable remove or comment out the line writer = journald
    writer needs to be set equal to file
    file variable needs to be set to path to where log file will be stored.
    # set writer = <path to log file>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000375-DB-000323"
  tag "gid": "V-58065"
  tag "rid": "SV-72495r1_rule"
  tag "stig_id": "SRG-APP-000375-DB-000323"
  tag "fix_id": nil
  tag "cci": ["CCI-001889"]
  tag "nist": ["AU-8 b", "Rev_4"]
  
  describe file(input('couchdb_conf_default')) do
    it { should exist }
  end
  describe ini(input('couchdb_conf_default')) do
  its('log.writer') { should_not match 'journald'}
  end
end

