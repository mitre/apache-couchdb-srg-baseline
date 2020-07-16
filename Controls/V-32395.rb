# encoding: UTF-8

control 'V-32395' do
  title "The audit information produced by the DBMS must be protected from
unauthorized deletion."
  desc  "If audit data were to become compromised, then competent forensic
analysis and discovery of the true source of potentially malicious system
activity is impossible to achieve.

    To ensure the veracity of audit data, the information system and/or the
application must protect audit information from unauthorized deletion. This
requirement can be achieved through multiple methods which will depend upon
system architecture and design.

    Some commonly employed methods include: ensuring log files enjoy the proper
file system permissions utilizing file system protections; restricting access;
and backing up log data to ensure log data is retained.

    Applications providing a user interface to audit data will leverage user
permissions and roles identifying the user accessing the data and the
corresponding rights the user enjoys in order make access decisions regarding
the deletion of audit data.

    Audit information includes all information (e.g., audit records, audit
settings, and audit reports) needed to successfully audit information system
activity.

    Deletion of database audit data could mask the theft of, or the
unauthorized modification of, sensitive data stored in the database.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the access permissions to tools used to view or modify audit
information produced by CouchDB. These tools may include features within
CouchDB itself or software external to the database.

    The file path to audit information produced by CouchDB is defined in the
default.ini configuration file. Only authorized users should have permission to
delete this information.

    Verify the permission of the log files produced by CouchDB with the
following commands:

      # find . -name \"default.ini\"
      # grep \"file =\" <path to default.ini>
      # ls -la <path of .ini file>

    If the audit information produced by CouchDB is not protected from
unauthorized deletion, this is a finding.
  "
  desc  'fix', "
    As the system administrator, change the permissions of the configuration
files:

      # find . -name \"default.ini\"
      # grep \"file =\" <path to default.ini>
      # sudo chown -R <Database Admin>:<Database Admin Group> <Log File>
      # sudo chmod 600 <Log File>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000120-DB-000061'
  tag gid: 'V-32395'
  tag rid: 'SV-42732r3_rule'
  tag stig_id: 'SRG-APP-000120-DB-000061'
  tag fix_id: nil
  tag ccii: CCI-000164
  tag nist: 'AU-9'
end

