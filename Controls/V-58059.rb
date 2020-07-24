# encoding: UTF-8

control "V-58059" do
  title "The DBMS must provide an immediate real-time alert to appropriate
support staff of all audit log failures. "
  desc  "It is critical for the appropriate personnel to be aware if a system
is at risk of failing to process audit logs as required. Without a real-time
alert, security personnel may be unaware of an impending failure of the audit
capability, and system operation may be adversely affected.

    The appropriate support staff include, at a minimum, the ISSO and the
DBA/SA.

    A failure of database auditing will result in either the database
continuing to function without auditing or in a complete halt to database
operations. When audit processing fails, appropriate personnel must be alerted
immediately to avoid further downtime or unaudited transactions.

    Alerts provide organizations with urgent messages. Real-time alerts provide
these messages immediately (i.e., the time from event detection to alert occurs
in seconds or less).
  "
  desc  "check", "
    Review the CouchDB database documentation and deployed configuration to
verify that the database is configured to provide an immediate real-time alert
to appropriate support staff of all audit log failures.

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.

    #grep \"write_delay = \" <path to default.ini>
    if line does not exist or is not set to 0, this is a finding.

    If it is not set to provide an immediate real-time alert to appropriate
support staff of all audit log failures, this is a finding.
  "
  desc  "fix", "
    Configure CouchDB log records to record an immediate real-time alert to
appropriate support staff of all audit log failures.

    # find . -name \"default.ini\"
    # set write_delay = 0
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000360-DB-000320"
  tag "gid": "V-58059"
  tag "rid": "SV-72489r2_rule"
  tag "stig_id": "SRG-APP-000360-DB-000320"
  tag "fix_id": nil
  tag "cci": ["CCI-001858"]
  tag "nist": ["AU-5 (2)", "Rev_4"]

  describe file(input('couchdb_conf_default')) do
    it { should exist }
  end
  describe ini(input('couchdb_conf_default')) do
  its('log.write_delay') { should eq '0'}
  end
end

