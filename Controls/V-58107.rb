# encoding: UTF-8

control "V-58107" do
  title "The DBMS must generate audit records when successful logons or
connections occur."
  desc  "For completeness of forensic analysis, it is necessary to track
who/what (a user or other principal) logs on to the DBMS."
  desc  "check", "
    For completeness of forensic analysis, it is necessary to track who/what (a
user or other principal) logs on to CouchDB.
    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.
    If it is not set to generate audit records when successful logons or
connections occur.
  "
  desc  "fix", "
    Configure CouchDB to generate audit records when successful logons or
connections occur.
    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000503-DB-000350"
  tag "gid": "V-58107"
  tag "rid": "SV-72537r1_rule"
  tag "stig_id": "SRG-APP-000503-DB-000350"
  tag "fix_id": nil
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
end

