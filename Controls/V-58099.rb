# encoding: UTF-8

control 'V-58099' do
  title "The DBMS must generate audit records when categories of information
(e.g., classification levels/security levels) are modified."
  desc  "Changes in categories of information must be tracked. Without an audit
trail, unauthorized access to protected data could go undetected.

    For detailed information on categorizing information, refer to FIPS
Publication 199, Standards for Security Categorization of Federal Information
and Information Systems, and FIPS Publication 200, Minimum Security
Requirements for Federal Information and Information Systems.
  "
  desc  'check', "
    Review the CouchDB database documentation and deployed configuration to
verify that the database is configured to log audit records for when when
categories of information (e.g., classification levels/security levels) are
modified.

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to log whenwhen categories of information (e.g.,
classification levels/security levels) are modified, this is a finding.
  "
  desc  'fix', "
    Configure CouchDB to generate audit records when categories of information
(e.g., classification levels/security levels) are modified.

    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000498-DB-000346'
  tag gid: 'V-58099'
  tag rid: 'SV-72529r1_rule'
  tag stig_id: 'SRG-APP-000498-DB-000346'
  tag fix_id: nil
  tag ccii: CCI-000172
  tag nist: 'AU-12 c'
end

