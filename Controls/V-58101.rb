# encoding: UTF-8

control 'V-58101' do
  title "The DBMS must generate audit records when unsuccessful attempts to
modify categories of information (e.g., classification levels/security levels)
occur."
  desc  "Changes in categories of information must be tracked. Without an audit
trail, unauthorized access to protected data could go undetected.

    To aid in diagnosis, it is necessary to keep track of failed attempts in
addition to the successful ones.

    For detailed information on categorizing information, refer to FIPS
Publication 199, Standards for Security Categorization of Federal Information
and Information Systems, and FIPS Publication 200, Minimum Security
Requirements for Federal Information and Information Systems.
  "
  desc  'check', "
     Review DBMS documentation to verify that audit records can be produced
when the system denies or fails to complete attempts to modify categories of
information.
    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.


    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.
    If it is not set to generate audit records when unsuccessful attempts to
modify categories of information (e.g., classification levels/security levels)
occur.
  "
  desc  'fix', "
    Configure CouchDB to generate audit records when unsuccessful attempts to
modify categories of information (e.g., classification levels/security levels)
occur.
    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000498-DB-000347"
  tag gid: "V-58101"
  tag rid: "SV-72531r1_rule"
  tag stig_id: "SRG-APP-000498-DB-000347"
  tag fix_id: nil
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c", "Rev_4"]
end

