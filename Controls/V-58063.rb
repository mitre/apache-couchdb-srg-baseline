# encoding: UTF-8

control "V-58063" do
  title "The DBMS must record time stamps, in audit records and application
data, that can be mapped to Coordinated Universal Time (UTC, formerly GMT)."
  desc  "If time stamps are not consistently applied and there is no common
time reference, it is difficult to perform forensic analysis.

    Time stamps generated by the DBMS must include date and time. Time is
commonly expressed in Coordinated Universal Time (UTC), a modern continuation
of Greenwich Mean Time (GMT), or local time with an offset from UTC.

    Some DBMS products offer a data type called TIMESTAMP that is not a
representation of date and time. Rather, it is a database state counter and
does not correspond to calendar and clock time. This requirement does not refer
to that meaning of TIMESTAMP.
  "
  desc  "check", "
    Review the CouchDB database documentation and deployed configuration to
verify that the database is configured to provide record time stamps, in audit
records and application data, that can be mapped to Coordinated Universal Time
(UTC, formerly GMT).

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"writer = \" <path to default.ini>
    if line is equal to journald, this is a finding.

    If it is not set to provide record time stamps, in audit records and
application data, that can be mapped to Coordinated Universal Time (UTC,
formerly GMT), this is a finding.
  "
  desc  "fix", "
    If applicable remove or comment out the line writer = journald
    writer needs to be set equal to file

    File variable needs to be set to path to where log file will be stored.
    # find . -name \"default.ini\"
    #writer = <path to log file>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000374-DB-000322"
  tag "gid": "V-58063"
  tag "rid": "SV-72493r1_rule"
  tag "stig_id": "SRG-APP-000374-DB-000322"
  tag "fix_id": nil
  tag "cci": ["CCI-001890"]
  tag "nist": ["AU-8 b", "Rev_4"]

  
  describe file(input('couchdb_conf_default')) do
    it { should exist }
  end
  describe ini(input('couchdb_conf_default')) do
  its('log.writer') { should eq 'journald'}
  end
end

