# encoding: UTF-8

control 'V-58127' do
  title "The DBMS must produce audit records of its enforcement of access
restrictions associated with changes to the configuration of the DBMS or
database(s)."
  desc  "Without auditing the enforcement of access restrictions against
changes to configuration, it would be difficult to identify attempted attacks
and an audit trail would not be available for forensic investigation for
after-the-fact actions.

    Enforcement actions are the methods or mechanisms used to prevent
unauthorized changes to configuration settings. Enforcement action methods may
be as simple as denying access to a file based on the application of file
permissions (access restriction). Audit items may consist of lists of actions
blocked by access restrictions or changes identified after the fact.
  "
  desc  'check', "
    Review the CouchDB documentation to verify that audit records can produce
audit records of its enforcement of access restrictions associated with changes
to the configuration of database(s).
    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to produce audit records of its enforcement of access
restrictions associated with changes to the configuration of the CouchDB
database, this is a finding.
  "
  desc  'fix', "
     Configure CouchDB to verify that audit records can produce audit records
of its enforcement of access restrictions associated with changes to the
configuration of database(s).

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000381-DB-000361'
  tag gid: 'V-58127'
  tag rid: 'SV-72557r1_rule'
  tag stig_id: 'SRG-APP-000381-DB-000361'
  tag fix_id: nil
  tag ccii: CCI-001814
  tag nist: 'CM-5 (1)'
end

