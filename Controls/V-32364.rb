# encoding: UTF-8

control 'V-32364' do
  title "The DBMS must be able to generate audit records when
privileges/permissions are retrieved."
  desc  "Under some circumstances, it may be useful to monitor who/what is
reading privilege/permission/role information. Therefore, it must be possible
to configure auditing to do this. DBMSs typically make such information
available through views or functions.

    This requirement addresses explicit requests for privilege/permission/role
membership information. It does not refer to the implicit retrieval of
privileges/permissions/role memberships that the DBMS continually performs to
determine if any and every action on the database is permitted.
  "
  desc  'check', "
     Check CouchDB settings and documentation and be able to generate audit
records when privileges/permissions are retrieved.
    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to generate audit records when privileges/permissions are
retrieved, this is a finding.
  "
  desc  'fix', "
    As the system administrator, change the permissions of the configuration
files:

      # sudo chown -R <Database Admin>:<Database Admin Group> <Configuration
file>
      # sudo chmod 600 <Configuration file>
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000091-DB-000066"
  tag gid: "V-32364"
  tag rid: "SV-42701r3_rule"
  tag stig_id: "SRG-APP-000091-DB-000066"
  tag fix_id: nil
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]
end

