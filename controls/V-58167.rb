# encoding: UTF-8

control "V-58167" do
  title "The DBMS must only accept end entity certificates issued by DoD PKI or
DoD-approved PKI Certification Authorities (CAs) for the establishment of all
encrypted sessions."
  desc  "Only DoD-approved external PKIs have been evaluated to ensure that
they have security controls and identity vetting procedures in place which are
sufficient for DoD systems to rely on the identity asserted in the certificate.
 PKIs lacking sufficient security controls and identity vetting procedures risk
being compromised and issuing certificates that enable adversaries to
impersonate legitimate users.

    The authoritative list of DoD-approved PKIs is published at
http://iase.disa.mil/pki-pke/interoperability.

    This requirement focuses on communications protection for the DBMS session
rather than for the network packet.
  "
  desc  "check", "
    Check for the following:
    # find . -name \"local.ini\"

    #grep  'ssl' section
    Verify \"enabled = true\"
    #grep 'cert_file = /etc/couchdb/cert/couchdb.pem'
    Verify for certificates issued by DoD PKI or DoD-approved PKI Certification
Authorities (CAs)

    If CouchDB will accept non-DoD approved PKI end-entity certificates, this
is a finding
  "
  desc  "fix", "Revoke trust in any certificates not issued by a DoD-approved
certificate authority. Configure CouchDB to accept only DoD and DoD-approved
PKI end-entity certificates."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000427-DB-000385"
  tag "gid": "V-58167"
  tag "rid": "SV-72597r1_rule"
  tag "stig_id": "SRG-APP-000427-DB-000385"
  tag "fix_id": nil
  tag "cci": ["CCI-002470"]
  tag "nist": ["SC-23 (5)", "Rev_4"]

  describe ini(input('couchdb_conf_local')) do
    its('ssl.enable') { should eq 'true' }
    its('ssl.cert_file') {should eq '/etc/couchdb/cert/couchdb.pem'}
    its('ssl.key_file') {should eq '/etc/couchdb/cert/privkey.pem'}
  end

  describe file(input('couchdbpem')) do
    it { should exist }
    its ('mode') { should be 0600 }
  end

  describe file(input('privkeypem')) do
    it { should exist }
    its ('mode') { should be 0600 }
  end 
end