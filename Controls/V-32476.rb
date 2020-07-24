# encoding: UTF-8

control "V-32476" do
  title "The DBMS must enforce authorized access to all PKI private keys
stored/utilized by the DBMS."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.
PKI certificate-based authentication is performed by requiring the certificate
holder to cryptographically prove possession of the corresponding private key.

    If the private key is stolen, an attacker can use the private key(s) to
impersonate the certificate holder.  In cases where the DBMS-stored private
keys are used to authenticate the DBMS to the system\xE2\x80\x99s clients, loss
of the corresponding private keys would allow an attacker to successfully
perform undetected man in the middle attacks against the DBMS system and its
clients.

    Both the holder of a digital certificate and the issuing authority must
take careful measures to protect the corresponding private key. Private keys
should always be generated and protected in FIPS 140-2 validated cryptographic
modules.

    All access to the private key(s) of the DBMS must be restricted to
authorized and authenticated users. If unauthorized users have access to one or
more of the DBMS's private keys, an attacker could gain access to the key(s)
and use them to impersonate the database on the network or otherwise perform
unauthorized actions.
  "
  desc  "check", "
    Review CouchDB configuration to determine whether appropriate access
controls exist to protect CouchDB's private key(s). If the CouchDB\x92s private
key(s) are not stored in a FIPS 140-2 validated cryptographic module, this is a
finding.

    # find . -name \"local.ini\"

    # grep ssl section
    # grep \"cacert_file =\" <path to local.ini>
    # grep \"cert_file =\" <path to local.ini>
    # grep \"key_file =\" <path to local.ini>

    If the directory these files are stored in is not protected, this is a
finding.
  "
  desc  "fix", "
    Store all CouchDB PKI private keys in a FIPS 140-2-validated cryptographic
module.

    Ensure access to Couch PKI private keys is restricted to only authenticated
and authorized users.

    Example:

    ssl_ca_file = \"/some/protected/directory/root.crt\"
    ssl_crl_file = \"/some/protected/directory/root.crl\"
    ssl_cert_file = \"/some/protected/directory/server.crt\"

  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000176-DB-000068"
  tag "gid": "V-32476"
  tag "rid": "SV-42813r3_rule"
  tag "stig_id": "SRG-APP-000176-DB-000068"
  tag "fix_id": nil
  tag "cci": ["CCI-000186"]
  tag "nist": ["IA-5 (2)", "Rev_4"]

  describe file(input('couchdb_conf_local')) do
    it { should exist }
  end
  describe ini(input('couchdb_conf_local')) do
    its('ssl.secure_renegotiate') { should eq 'true' }
    its('ssl.cert_file') {should eq '/etc/couchdb/cert/couchdb.pem'}
    its('ssl.cacert_file') {should eq '/etc/ssl/certs/ca-certificates.crt'}
    its('ssl.key_file') {should eq '/etc/couchdb/cert/privkey.pem'}

  end
end

