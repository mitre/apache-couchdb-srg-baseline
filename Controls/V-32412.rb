# encoding: UTF-8

control "V-32412" do
  title "Database objects (including but not limited to tables, indexes,
storage, stored procedures, functions, triggers, links to software external to
the DBMS, etc.) must be owned by database/DBMS principals authorized for
ownership."
  desc  "Within the database, object ownership implies full privileges to the
owned object, including the privilege to assign access to the owned objects to
other subjects. Database functions and procedures can be coded using definer's
rights. This allows anyone who utilizes the object to perform the actions if
they were the owner. If not properly managed, this can lead to privileged
actions being taken by unauthorized individuals.

    Conversely, if critical tables or other objects rely on unauthorized owner
accounts, these objects may be lost when an account is removed.
  "
  desc  "check", "
    Review system documentation to identify accounts authorized to own database
objects. Review accounts that own objects in the database(s).

    If any database objects are found to be owned by users not authorized to
own database objects, this is a finding.
    Check for the following:

    Execute the command
     #GET /db/_security
    #grep names and verify that all users are authorized to own
database objects.
  "
  desc  "fix", "
    Assign ownership of authorized objects to authorized object owner accounts.
    Use the following command to set privileges correctly:

    # PUT /{db}/_security

  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000200"
  tag "gid": "V-32412"
  tag "rid": "SV-42749r3_rule"
  tag "stig_id": "SRG-APP-000133-DB-000200"
  tag "fix_id": nil
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]

  admin_roles = input('approved_admin')

  admin_name = input('couchdb_admin')

  admin_pass = input ('couchdb_adminpass')

  database = input('couchdb_db')

  port = input('couch_port')
  host = input('couch_host')
  admin_roles.each do |role|
    describe command('curl -X GET ' + admin_name + ':' + admin_pass + '@' + host + ':' + port + '/_node/_local/_config/admins') do
    its('stdout') { should include role }
    end
  end
end


