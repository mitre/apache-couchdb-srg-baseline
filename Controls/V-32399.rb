# encoding: UTF-8

control 'V-32399' do
  title 'The DBMS must protect its audit features from unauthorized removal.'
  desc  "Protecting audit data also includes identifying and protecting the
tools used to view and manipulate log data. Therefore, protecting audit tools
is necessary to prevent unauthorized operation on audit data.

    Applications providing tools to interface with audit data will leverage
user permissions and roles identifying the user accessing the tools and the
corresponding rights the user enjoys in order make access decisions regarding
the deletion of audit tools.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.
  "
  desc  'check', "
    Review the access permissions to tools used to view or modify audit log
data. These tools may include features within CouchDB itself or software
external to the database.

    Logging configuration is defined in the default.ini configuration file and
other .ini files. These files should be owned by the database administrator.

    Verify the permission of the .ini files with the following commands:

    \xA0 # find . -name \"*.ini\"
    \xA0 # ls -la <path of .ini file>

    If any of these .ini files are not owned by the database administrator,
this is a finding.
  "
  desc  'fix', "
    As the system administrator, change the permissions of the configuration
files:

    \xA0 # sudo chown -R <Database Admin>:<Database Admin Group> <Configuration
file>
    \xA0 # sudo chmod 600 <Configuration file>
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000123-DB-000204"
  tag gid: "V-32399"
  tag rid: "SV-42736r3_rule"
  tag stig_id: "SRG-APP-000123-DB-000204"
  tag fix_id: nil
  tag cci: ["CCI-001495"]
  tag nist: ["AU-9"]
end

