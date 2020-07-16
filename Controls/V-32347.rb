# encoding: UTF-8

control 'V-32347' do
  title "The DBMS must protect against a user falsely repudiating having
performed organization-defined actions."
  desc  "Non-repudiation of actions taken is required in order to maintain data
integrity. Examples of particular actions taken by individuals include creating
information, sending a message, approving information (e.g., indicating
concurrence or signing a contract), and receiving a message.

    Non-repudiation protects against later claims by a user of not having
created, modified, or deleted a particular data item or collection of data in
the database.

    In designing a database, the organization must define the types of data and
the user actions that must be protected from repudiation. The implementation
must then include building audit features into the application data tables and
configuring the DBMS's audit tools to capture the necessary audit trail. Design
and implementation also must ensure that applications pass individual user
identification to the DBMS, even where the application connects to the DBMS
with a standard, shared account.
  "
  desc  'check', "
    Check CouchDB settings and documentation and protect against a user falsely
repudiating having performed organization-defined actions.
    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    # grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to protect against a user falsely repudiating having
performed organization-defined actions, this is a finding.
  "
  desc  'fix', "
    Configure CouchDB to and protect against a user falsely repudiating having
performed organization-defined actions.
    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000080-DB-000063"
  tag gid: "V-32347"
  tag rid: "SV-42684r4_rule"
  tag stig_id: "SRG-APP-000080-DB-000063"
  tag fix_id: nil
  tag cci: ["CCI-000166"]
  tag nist: ["AU-10"]
end

