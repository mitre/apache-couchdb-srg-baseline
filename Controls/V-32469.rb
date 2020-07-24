# encoding: UTF-8

control "V-32469" do
  title "If passwords are used for authentication, the DBMS must transmit only
encrypted representations of passwords."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.

    Authentication based on User ID and Password may be used only when it is
not possible to employ a PKI certificate, and requires AO approval.

    In such cases, passwords need to be protected at all times, and encryption
is the standard method for protecting passwords during transmission.

    DBMS passwords sent in clear text format across the network are vulnerable
to discovery by unauthorized users. Disclosure of passwords may easily lead to
unauthorized access to the database.
  "
  desc  "check", "
    Review the CouchDB database settings relating to passwords are used for
authentication, CouchDB must transmit only encrypted representations of
passwords.

    CouchDB salts and hashes passwords automatically, but can be verified by:
    # find . -name \"local.ini\"
    #cat <path to local.ini>
    Review this file for users along with passwords. It can be seen in the
following format:
    admin =
-pbkdf2-71c01cb429088ac1a1e95f3482202622dc1e53fe,226701bece4ae0fc9a373a5e02bf5d07,10

    The -pbkdf2- at the begining indicates that it is hashed. If this pre-fix
is not there, this is a finding.
  "
  desc  "fix", "
    Restart the CouchDB services.
    # sudo restart couchdb
    CouchDB documentation outlines that during startup it is verified that
passwords are hashed and if it is not, then it is done then.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000172-DB-000075"
  tag "gid": "V-32469"
  tag "rid": "SV-42806r3_rule"
  tag "stig_id": "SRG-APP-000172-DB-000075"
  tag "fix_id": nil
  tag "cci": ["CCI-000197"]
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]

  describe file(input('couchdb_conf_local')) do
    it { should exist }
  end

  describe ini(input('couchdb_conf_local')) do
    its('admins.admin') { should match '-pbkdf2-' }
  end
end

