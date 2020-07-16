# encoding: UTF-8

control 'V-58055' do
  title "The DBMS must off-load audit data to a separate log management
facility; this shall be continuous and in near real time for systems with a
network connection to the storage facility and weekly or more often for
stand-alone systems."
  desc  "Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.

    The DBMS may write audit records to database tables, to files in the file
system, to other kinds of local repository, or directly to a centralized log
management system. Whatever the method used, it must be compatible with
off-loading the records to the centralized system.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the system documentation for a description of how audit records are
off-loaded.

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep 'syslog_facility'
    Check with the organization to see how syslog facilities are defined in
their organization.

    If the wrong facility is configured, this is a finding.

    If CouchDB has a continuous network connection to the centralized log
management system, but CouchDB audit records are not written directly to the
centralized log management system or transferred in near-real-time, this is a
finding.

    If CouchDB does not have a continuous network connection to the centralized
log management system, and CouchDB audit records are not transferred to the
centralized log management system weekly or more often, this is a finding.
  "
  desc  'fix', "
    Configure CouchDB to off-load audit data to a separate log management
facility; this shall be continuous and in near real time for systems with a
network connection to the storage facility and weekly or more often for
stand-alone systems.

    Ensure logging is enabled
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag gid: 'V-58055'
  tag rid: 'SV-72485r1_rule'
  tag stig_id: 'SRG-APP-000515-DB-000318'
  tag fix_id: nil
  tag ccii: CCI-001851
  tag nist: 'AU-4 (1)'
end

