# encoding: UTF-8

control 'V-32369' do
  title "The DBMS must produce audit records containing time stamps to
establish when the events occurred."
  desc  "Information system auditing capability is critical for accurate
forensic analysis. Without establishing when events occurred, it is impossible
to establish, correlate, and investigate the events relating to an incident.

    In order to compile an accurate risk assessment and provide forensic
analysis, it is essential for security personnel to know the date and time when
events occurred.

    Associating the date and time with detected events in the application and
audit logs provides a means of investigating an attack; recognizing resource
utilization or capacity thresholds; or identifying an improperly configured
application.

    Database software is capable of a range of actions on data stored within
the database. It is important, for accurate forensic analysis, to know exactly
when specific actions were performed. This requires the date and time an audit
record is referring to. If date and time information is not recorded and stored
with the audit record, the record itself is of very limited use.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the CouchDB database documentation and deployed configuration to
verify that the database is configured to produce audit records containing time
stamps to establish when the events occurred.

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"writer = \" <path to default.ini>
    if line is equal to journald, this is a finding.

    If it is not set to produce audit records containing time stamps to
establish when the events occurred, this is a finding.
  "
  desc  'fix', "
    If applicable remove or comment out the line writer = journald
    writer needs to be set equal to file.
    File variable needs to be set to path to where log file will be stored.
    # set writer = <path to log file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000096-DB-000040'
  tag gid: 'V-32369'
  tag rid: 'SV-42706r3_rule'
  tag stig_id: 'SRG-APP-000096-DB-000040'
  tag fix_id: nil
  tag cci: "CCI-000131
The information system generates audit records containing information that
establishes when an event occurred.
NIST SP 800-53 :: AU-3
NIST SP 800-53A :: AU-3.1
NIST SP 800-53 Revision 4 :: AU-3

"
  tag nist: 'AU-3'
end

