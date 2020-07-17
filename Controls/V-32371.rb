# encoding: UTF-8

control "V-32371" do
  title "The DBMS must produce audit records containing sufficient information
to establish the sources (origins) of the events."
  desc  "Information system auditing capability is critical for accurate
forensic analysis. Without establishing the source of the event, it is
impossible to establish, correlate, and investigate the events relating to an
incident.

    In order to compile an accurate risk assessment and provide forensic
analysis, it is essential for security personnel to know where events occurred,
such as application components, modules, session identifiers, filenames, host
names, and functionality.

    In addition to logging where events occur within the application, the
application must also produce audit records that identify the application
itself as the source of the event.

    Associating information about the source of the event within the
application provides a means of investigating an attack; recognizing resource
utilization or capacity thresholds; or identifying an improperly configured
application.
  "
  desc  "check", "
     Check CouchDB settings and documentation produce audit records containing
sufficient information to establish the sources (origins) of the events.
    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to produce audit records containing sufficient information
to establish the sources (origins) of the events, this is a finding.
  "
  desc  "fix", "
    Configure CouchDB to produce audit records containing sufficient
information to establish the sources (origins) of the events.
    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000098-DB-000042"
  tag "gid": "V-32371"
  tag "rid": "SV-42708r3_rule"
  tag "stig_id": "SRG-APP-000098-DB-000042"
  tag "fix_id": nil
  tag "cci": ["CCI-000133"]
  tag "nist": ["AU-3", "Rev_4"]
end

