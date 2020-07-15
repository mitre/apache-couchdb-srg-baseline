# encoding: UTF-8

control 'V-58091' do
  title "The DBMS must generate audit records when security objects are
deleted."
  desc  "The removal of security objects from the database/DBMS would seriously
degrade a system's information assurance posture. If such an event occurs, it
must be logged."
  desc  'rationale', ''
  desc  'check', "
    Review the CouchDB database documentation and deployed configuration to
verify that the database is configured to log audit records for when security
objects are deleted.

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.

    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to log  when security objects are deleted., this is a
finding.
  "
  desc  'fix', "
    Configure CouchDB to generate audit records when security objects are
deleted.

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000501-DB-000336'
  tag gid: 'V-58091'
  tag rid: 'SV-72521r1_rule'
  tag stig_id: 'SRG-APP-000501-DB-000336'
  tag fix_id: nil
  tag cci: "CCI-000172
The information system generates audit records for the events defined in AU-2 d
with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c

"
  tag nist: 'AU-12 c'
end

