# encoding: UTF-8

control "V-58157" do
  title "The DBMS must use NSA-approved cryptography to protect classified
information in accordance with the data owners requirements."
  desc  "Use of weak or untested encryption algorithms undermines the purposes
of utilizing encryption to protect data. The application must implement
cryptographic modules adhering to the higher standards approved by the federal
government since this provides assurance they have been tested and validated.

    It is the responsibility of the data owner to assess the cryptography
requirements in light of applicable federal laws, Executive Orders, directives,
policies, regulations, and standards.

    NSA-approved cryptography for classified networks is hardware based. This
requirement addresses the compatibility of a DBMS with the encryption devices.
  "
  desc  "check", "
    If CouchDB is deployed in an unclassified environment, this is not
applicable (NA).

    # find . -name \"local.ini\"
    # grep \"ssl section\"
    # grep \"enable =\"
    If this is not set equal to true, this is a finding.
  "
  desc  "fix", "
    Configure CouchDB to use SSL
    # find . -name \"local.ini\"
    # set \"enable=true\"
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000416-DB-000380"
  tag "gid": "V-58157"
  tag "rid": "SV-72587r1_rule"
  tag "stig_id": "SRG-APP-000416-DB-000380"
  tag "fix_id": "F-63365r1_fix"
  tag "cci": ["CCI-002450"]
  tag "nist": ["SC-13", "Rev_4"]

  describe ini(input('couchdb_conf_local')) do
    its('ssl.enable') { should eq 'true' }
  end
end

