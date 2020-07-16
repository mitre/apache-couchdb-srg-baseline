# encoding: UTF-8

control 'V-58163' do
  title "The DBMS must implement NIST FIPS 140-2 validated cryptographic
modules to protect unclassified information requiring confidentiality and
cryptographic protection, in accordance with the data owners requirements."
  desc  "Use of weak or untested encryption algorithms undermines the purposes
of utilizing encryption to protect data. The application must implement
cryptographic modules adhering to the higher standards approved by the federal
government since this provides assurance they have been tested and validated.

    It is the responsibility of the data owner to assess the cryptography
requirements in light of applicable federal laws, Executive Orders, directives,
policies, regulations, and standards.

    For detailed information, refer to NIST FIPS Publication 140-2, Security
Requirements For Cryptographic Modules. Note that the product's cryptographic
modules must be validated and certified by NIST as FIPS-compliant.
  "
  desc  'check', "
    Check for the following:
    # find . -name \"local.ini\"

    # cat /proc/sys/crypto/fips_enabled
    Verify that the response of \x91fips_enabled\x92 is 1.

    If it is not 1 , this is a finding.
  "
  desc  'fix', "
    Configure OpenSSL to be FIPS compliant.
    # sed -i 's/0/1/g' /proc/sys/crypto/fips_enabled
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000514-DB-000383"
  tag gid: "V-58163"
  tag rid: "SV-72593r1_rule"
  tag stig_id: "SRG-APP-000514-DB-000383"
  tag fix_id: nil
  tag cci: ["CCI-002450"]
  tag nist: ["SC-13"]
end

