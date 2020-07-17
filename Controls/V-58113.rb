# encoding: UTF-8

control "V-58113" do
  title "The DBMS must generate audit records when concurrent
logons/connections by the same user from different workstations occur."
  desc  "For completeness of forensic analysis, it is necessary to track who
logs on to the DBMS.

    Concurrent connections by the same user from multiple workstations may be
valid use of the system; or such connections may be due to improper
circumvention of the requirement to use the CAC for authentication; or they may
indicate unauthorized account sharing; or they may be because an account has
been compromised.

    (If the fact of multiple, concurrent logons by a given user can be reliably
reconstructed from the log entries for other events (logons/connections;
voluntary and involuntary disconnections), then it is not mandatory to create
additional log entries specifically for this.)
  "
  desc  "check", "
    Review the CouchDB database documentation and deployed configuration to
verify that the database is configured to log audit records when concurrent
logons/connections by the same user from different workstations occur.

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to log audit records when concurrent logons/connections by
the same user from different workstations occur, this is a finding.
  "
  desc  "fix", "
    Configure CouchDB to generate audit records when concurrent
logons/connections by the same user from different workstations occur.

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000506-DB-000353"
  tag "gid": "V-58113"
  tag "rid": "SV-72543r1_rule"
  tag "stig_id": "SRG-APP-000506-DB-000353"
  tag "fix_id": nil
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
end

