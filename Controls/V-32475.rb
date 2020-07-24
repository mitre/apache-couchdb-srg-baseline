# encoding: UTF-8

control "V-32475" do
  title "The DBMS, when utilizing PKI-based authentication, must validate
certificates by performing RFC 5280-compliant certification path validation."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.

    A certificate\xE2\x80\x99s certification path is the path from the end
entity certificate to a trusted root certification authority (CA).
Certification path validation is necessary for a relying party to make an
informed decision regarding acceptance of an end entity certificate.
Certification path validation includes checks such as certificate issuer trust,
time validity and revocation status for each certificate in the certification
path.  Revocation status information for CA and subject certificates in a
certification path is commonly provided via certificate revocation lists (CRLs)
or online certificate status protocol (OCSP) responses.

    Database Management Systems that do not validate certificates by performing
RFC 5280-compliant certification path validation are in danger of accepting
certificates that are invalid and/or counterfeit. This could allow unauthorized
access to the database.
  "
  desc  "check", "
    # find local.ini
    # grep \"cacert_file =\" <path to local.ini>
    If cacert_file path does not exist, this is a finding.
    # grep \"cert_file =\" <path to local.ini>
    If cert_file path does not exist, this is a finding.
    # grep \"secure_renegotiate\" <path to local.ini>
    If commented out, or not set to true, this is a finding.

    If certificates are not being validated by performing RFC 5280-compliant
certification path validation, this is a finding.
  "
  desc  "fix", "
    # find local.ini
    # set secure_renegotiate = true
    # set cacert_file = <cert path>
    # set cert_file = <cert path>

    Verify certificates are being validated by performing RFC 5280-compliant
certification path validation.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000175-DB-000067"
  tag "gid": "V-32475"
  tag "rid": "SV-42812r3_rule"
  tag "stig_id": "SRG-APP-000175-DB-000067"
  tag "fix_id": "F-36390r3_fix"
  tag "cci": ["CCI-000185"]
  tag "nist": ["IA-5 (2) (a)", "Rev_4"]

  describe file(input('couchdb_conf_local')) do
    it { should exist }
  end
  describe ini(input('couchdb_conf_local')) do
    its('ssl.secure_renegotiate') { should eq 'true' }
    its('ssl.cert_file') {should eq '/etc/couchdb/cert/couchdb.pem'}
    its('ssl.cacert_file') {should eq '/etc/ssl/certs/ca-certificates.crt'}

  end
end

