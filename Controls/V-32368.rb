# encoding: UTF-8

control 'V-32368' do
  title "The DBMS must produce audit records containing sufficient information
to establish what type of events occurred."
  desc  "Information system auditing capability is critical for accurate
forensic analysis. Without establishing what type of event occurred, it would
be difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    Audit record content that may be necessary to satisfy the requirement of
this policy includes, for example, time stamps, user/process identifiers, event
descriptions, success/fail indications, filenames involved, and access control
or flow control rules invoked.

    Associating event types with detected events in the application and audit
logs provides a means of investigating an attack; recognizing resource
utilization or capacity thresholds; or identifying an improperly configured
application.

    Database software is capable of a range of actions on data stored within
the database. It is important, for accurate forensic analysis, to know exactly
what actions were performed. This requires specific information regarding the
event type an audit record is referring to. If event type information is not
recorded and stored with the audit record, the record itself is of very limited
use.
  "
  desc  'rationale', ''
  desc  'check', "
     Check CouchDB settings and documentation produce audit records containing
sufficient information to establish what type of events occurred.
    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to produce audit records containing sufficient information
to establish what type of events occurred, this is a finding.
  "
  desc  'fix', "
    Configure CouchDB to produce audit records containing sufficient
information to establish what type of events occurred.
    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000095-DB-000039'
  tag gid: 'V-32368'
  tag rid: 'SV-42705r3_rule'
  tag stig_id: 'SRG-APP-000095-DB-000039'
  tag fix_id: nil
  tag cci: "CCI-000130
The information system generates audit records containing information that
establishes what type of event occurred.
NIST SP 800-53 :: AU-3
NIST SP 800-53A :: AU-3.1
NIST SP 800-53 Revision 4 :: AU-3

"
  tag nist: 'AU-3'
end

