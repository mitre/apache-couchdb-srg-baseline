# encoding: UTF-8

control 'V-32397' do
  title 'The DBMS must protect its audit features from unauthorized access.'
  desc  "Protecting audit data also includes identifying and protecting the
tools used to view and manipulate log data.

    Depending upon the log format and application, system and application log
tools may provide the only means to manipulate and manage application and
system log data. It is, therefore, imperative that access to audit tools be
controlled and protected from unauthorized access.

    Applications providing tools to interface with audit data will leverage
user permissions and roles identifying the user accessing the tools and the
corresponding rights the user enjoys in order make access decisions regarding
the access to audit tools.

    Audit tools include, but are not limited to, OS-provided audit tools,
vendor-provided audit tools, and open source audit tools needed to successfully
view and manipulate audit information system activity and records.

    If an attacker were to gain access to audit tools, he could analyze audit
logs for system weaknesses or weaknesses in the auditing itself. An attacker
could also manipulate logs to hide evidence of malicious activity.
  "
  desc  'check', "
    Review the access permissions to tools used to view or modify audit log
configurations. These tools may include features within CouchDB itself or
software external to the database.

    Logging configuration is defined in the default.ini configuration file and
other .ini files. Only authorized users should have permissions to the file.

    Verify the permission of the .ini files with the following commands:

      # find . -name \"*.ini\"
      # ls -la <path of .ini file>

    If any audit features can be accessed by unathorized users, this is a
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
  tag severity: "medium"
  tag gtitle: "SRG-APP-000121-DB-000202"
  tag gid: "V-32397"
  tag rid: "SV-42734r3_rule"
  tag stig_id: "SRG-APP-000121-DB-000202"
  tag fix_id: nil
  tag cci: ["CCI-001493"]
  tag nist: ["AU-9"]
end

