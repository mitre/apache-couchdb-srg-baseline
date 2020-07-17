# encoding: UTF-8

control "V-32365" do
  title 'The DBMS must initiate session auditing upon startup.'
  desc  "Session auditing is for use when a user's activities are under
investigation. To be sure of capturing all activity during those periods when
session auditing is in use, it needs to be in operation for the whole time the
DBMS is running."
  desc  "check", "
     Check CouchDB settings and documentation initiate session auditing upon
startup.
    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to initiate session auditing upon startup, this is a
finding.
  "
  desc  "fix", "
    Configure CouchDB to be able to generate audit records when
privileges/permissions are retrieved.
    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000092-DB-000208"
  tag "gid": "V-32365"
  tag "rid": "SV-42702r2_rule"
  tag "stig_id": "SRG-APP-000092-DB-000208"
  tag "fix_id": nil
  tag "cci": ["CCI-001464"]
  tag "nist": ["AU-14 (1)", "Rev_4"]
end

