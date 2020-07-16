# encoding: UTF-8

control 'V-32398' do
  title "The DBMS must protect its audit configuration from unauthorized
modification."
  desc  "Protecting audit data also includes identifying and protecting the
tools used to view and manipulate log data. Therefore, protecting audit tools
is necessary to prevent unauthorized operation on audit data.

    Applications providing tools to interface with audit data will leverage
user permissions and roles identifying the user accessing the tools and the
corresponding rights the user enjoys in order make access decisions regarding
the modification of audit tools.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the access permissions to tools used to view or modify audit log
configurations. These tools may include features within CouchDB itself or
software external to the database.

    Logging configuration is defined in the default.ini configuration file and
other .ini files. Only authorized users should have permission to modify
configuration files.

    Verify the permission of the .ini files with the following commands:

      # find . -name \"*.ini\"
      # ls -la <path of .ini file>

    If any audit features can be modified by unathorized users, this is a
finding.
  "
  desc  'fix', "
    As the system administrator, change the permissions of the configuration
files:

      # sudo chown -R <Database Admin>:<Database Admin Group> <Configuration
file>
      # sudo chmod 600 <Configuration file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000122-DB-000203'
  tag gid: 'V-32398'
  tag rid: 'SV-42735r3_rule'
  tag stig_id: 'SRG-APP-000122-DB-000203'
  tag fix_id: nil
  tag ccii: CCI-001494
  tag nist: 'AU-9'
end

