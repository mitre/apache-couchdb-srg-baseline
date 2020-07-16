# encoding: UTF-8

control 'V-58111' do
  title "The DBMS must generate audit records showing starting and ending time
for user access to the database(s)."
  desc  "For completeness of forensic analysis, it is necessary to know how
long a user's (or other principal's) connection to the DBMS lasts. This can be
achieved by recording disconnections, in addition to logons/connections, in the
audit logs.

    Disconnection may be initiated by the user or forced by the system (as in a
timeout) or result from a system or network failure. To the greatest extent
possible, all disconnections must be logged.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the CouchDB database documentation and deployed configuration to
verify that the database is configured to log audit records showing starting
and ending time for user access to the database(s).

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.

    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to log start and end times of user access, this is a
finding.
  "
  desc  'fix', "
    Configure CouchDB to generate audit records showing starting and ending
time for user access to the database(s).

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000505-DB-000352'
  tag gid: 'V-58111'
  tag rid: 'SV-72541r1_rule'
  tag stig_id: 'SRG-APP-000505-DB-000352'
  tag fix_id: nil
  tag ccii: CCI-000172
  tag nist: 'AU-12 c'
end

