# encoding: UTF-8

control "V-32370" do
  title "The DBMS must produce audit records containing sufficient information
to establish where the events occurred."
  desc  "Information system auditing capability is critical for accurate
forensic analysis. Without establishing where events occurred, it is impossible
to establish, correlate, and investigate the events relating to an incident.

    In order to compile an accurate risk assessment and provide forensic
analysis, it is essential for security personnel to know where events occurred,
such as application components, modules, session identifiers, filenames, host
names, and functionality.

    Associating information about where the event occurred within the
application provides a means of investigating an attack; recognizing resource
utilization or capacity thresholds; or identifying an improperly configured
application.
  "
  desc  "check", "
    Check CouchDB settings and existing audit records to verify information
specific to where the event occurred is being captured and stored with the
audit records.

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep file = /var/log/couchdb/couch.log

    If line does not exist, this is a finding.
  "
  desc  "fix", "
    Configure CouchDB audit settings to include where the event occurred as
part of the audit record.
    File variable needs to be set to path to where log file will be stored.
    #writer = file
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000097-DB-000041"
  tag "gid": "V-32370"
  tag "rid": "SV-42707r3_rule"
  tag "stig_id": "SRG-APP-000097-DB-000041"
  tag "fix_id": nil
  tag "cci": ["CCI-000132"]
  tag "nist": ["AU-3", "Rev_4"]
end

