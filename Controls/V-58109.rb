# encoding: UTF-8

control 'V-58109' do
  title "The DBMS must generate audit records when unsuccessful logons or
connection attempts occur."
  desc  "For completeness of forensic analysis, it is necessary to track failed
attempts to log on to the DBMS. While positive identification may not be
possible in a case of failed authentication, as much information as possible
about the incident must be captured."
  desc  'check', "
    Review CouchDB audit settings. If an audit record is not generated each
time a user (or other principal) attempts but fails to log on or connect to
CouchDB (including attempts where the user ID is invalid/unknown), this is a
finding.
    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.
    If it is not set to generate audit records when unsuccessful logons or
connection attempts occur.
  "
  desc  'fix', "
    Configure CouchDB to generate audit records when unsuccessful logons or
connection attempts occur.
    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000503-DB-000351'
  tag gid: 'V-58109'
  tag rid: 'SV-72539r1_rule'
  tag stig_id: 'SRG-APP-000503-DB-000351'
  tag fix_id: nil
  tag ccii: CCI-000172
  tag nist: 'AU-12 c'
end

