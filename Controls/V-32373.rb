# encoding: UTF-8

control 'V-32373' do
  title "The DBMS must produce audit records containing sufficient information
to establish the outcome (success or failure) of the events."
  desc  "Information system auditing capability is critical for accurate
forensic analysis. Without information about the outcome of events, security
personnel cannot make an accurate assessment as to whether an attack was
successful or if changes were made to the security state of the system.

    Event outcomes can include indicators of event success or failure and
event-specific results (e.g., the security state of the information system
after the event occurred). As such, they also provide a means to measure the
impact of an event and help authorized personnel to determine the appropriate
response.
  "
  desc  'rationale', ''
  desc  'check', "
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
  desc  'fix', "
    Configure CouchDB to produce audit records containing sufficient
information to establish the sources (origins) of the events.
    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000099-DB-000043'
  tag gid: 'V-32373'
  tag rid: 'SV-42710r3_rule'
  tag stig_id: 'SRG-APP-000099-DB-000043'
  tag fix_id: nil
  tag cci: "CCI-000134
The information system generates audit records containing information that
establishes the outcome of the event.
NIST SP 800-53 :: AU-3
NIST SP 800-53A :: AU-3.1
NIST SP 800-53 Revision 4 :: AU-3

"
  tag nist: 'AU-3'
end

