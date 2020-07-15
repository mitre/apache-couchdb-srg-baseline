# encoding: UTF-8

control 'V-32468' do
  title "If passwords are used for authentication, the DBMS must store only
hashed, salted representations of passwords."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.

    Authentication based on User ID and Password may be used only when it is
not possible to employ a PKI certificate, and requires AO approval.

    In such cases, database passwords stored in clear text, using reversible
encryption, or using unsalted hashes would be vulnerable to unauthorized
disclosure. Database passwords must always be in the form of one-way, salted
hashes when stored internally or externally to the DBMS.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the CouchDB database settings relating to passwords that are used
for authentication, the CouchDB database must store only hashed, salted
representations of passwords.

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
  desc  'fix', "
    Restart the CouchDB services.
    # sudo restart couchdb
    CouchDB documentation outlines that during startup it is verified that
passwords are hashed and if it is not, then it is done then.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag gid: 'V-32468'
  tag rid: 'SV-42805r3_rule'
  tag stig_id: 'SRG-APP-000171-DB-000074'
  tag fix_id: nil
  tag cci: "CCI-000196
The information system, for password-based authentication, stores only
encrypted representations of passwords.
NIST SP 800-53 :: IA-5 (1) (c)
NIST SP 800-53A :: IA-5 (1).1 (v)
NIST SP 800-53 Revision 4 :: IA-5 (1) (c)

"
  tag nist: 'IA-5 (1) (c)'
end

