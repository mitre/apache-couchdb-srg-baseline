# encoding: UTF-8

control "V-61407" do
  title "If DBMS authentication, using passwords, is employed, the DBMS must
enforce the DoD standards for password complexity and lifetime."
  desc  "OS/enterprise authentication and identification must be used
(SRG-APP-000023-DB-000001).  Native DBMS authentication may be used only when
circumstances make it unavoidable; and must be documented and AO-approved.

    The DoD standard for authentication is DoD-approved PKI certificates.
Authentication based on User ID and Password may be used only when it is not
possible to employ a PKI certificate, and requires AO approval.

    In such cases, the DoD standards for password complexity and lifetime must
be implemented.  DBMS products that can inherit the rules for these from the
operating system or access control program (e.g., Microsoft Active Directory)
must be configured to do so.  For other DBMSs, the rules must be enforced using
available configuration parameters or custom code.
  "
  desc  "check", "
    Review CouchDB settings relating to password complexity. Determine whether
the following rules are enforced. If any are not, this is a finding.


    Review CouchDB settings relating to password lifetime. Determine whether
the following rules are enforced. If any are not, this is a finding.

    # find . -name \"default.ini\"

    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.

    #cat <path to local.ini>
    Review this file for users along with passwords. It can be seen in the
following format:

    admin =
-pbkdf2-71c01cb429088ac1a1e95f3482202622dc1e53fe,226701bece4ae0fc9a373a5e02bf5d07,10


    Verify that the password follows the PBKDF2 (RFC-2898) algorithm

  "
  desc  "fix", "
    Restart the CouchDB services.
    # sudo restart couchdb
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000164-DB-000401"
  tag "gid": "V-61407"
  tag "rid": "SV-75897r3_rule"
  tag "stig_id": "SRG-APP-000164-DB-000401"
  tag "fix_id": "F-67323r7_fix"
  tag "cci": ["CCI-000192"]
  tag "nist": ["IA-5 (1) (a)", "Rev_4"]

  
  describe file(input('couchdb_conf_local')) do
    it { should exist }
  end

  describe ini(input('couchdb_conf_local')) do
    its('admins.admin') { should match '-pbkdf2-' }
  end

end

