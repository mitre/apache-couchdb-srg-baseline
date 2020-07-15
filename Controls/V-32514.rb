# encoding: UTF-8

control 'V-32514' do
  title "The DBMS must separate user functionality (including user interface
services) from database management functionality."
  desc  "Information system management functionality includes functions
necessary to administer databases, network components, workstations, or servers
and typically requires privileged user access.

    The separation of user functionality from information system management
functionality is either physical or logical and is accomplished by using
different computers, different central processing units, different instances of
the operating system, different network addresses, combinations of these
methods, or other methods, as appropriate.

    An example of this type of separation is observed in web administrative
interfaces that use separate authentication methods for users of any other
information system resources.

    This may include isolating the administrative interface on a different
domain and with additional access controls.

    If administrative functionality or information regarding DBMS management is
presented on an interface available for users, information on DBMS settings may
be inadvertently made available to the user.
  "
  desc  'rationale', ''
  desc  'check', "
    Check DBMS settings and vendor documentation to verify that administrative
functionality is separate from user functionality.

    If administrator and general user functionality are not separated either
physically or logically, this is a finding.
    #grep \x91roles\x92 for a list of user roles.
    If any non-administrative role has the attribute \"Superuser\", \"Create
role\", \"Create DB\" or \"Bypass RLS\", this is a finding.

    If administrator and general user functionality are not separated either
physically or logically, this is a finding.
  "
  desc  'fix', "
    Configure CouchDB to separate database administration and general user
functionality.

    Do not grant superuser, create role, create db or bypass rls role
attributes to users that do not require it.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-DB-000122'
  tag gid: 'V-32514'
  tag rid: 'SV-42851r3_rule'
  tag stig_id: 'SRG-APP-000211-DB-000122'
  tag fix_id: nil
  tag cci: "CCI-001082
The information system separates user functionality (including user interface
services) from information system management functionality.
NIST SP 800-53 :: SC-2
NIST SP 800-53A :: SC-2.1
NIST SP 800-53 Revision 4 :: SC-2

"
  tag nist: 'SC-2'
end

