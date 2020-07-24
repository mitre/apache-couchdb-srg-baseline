# encoding: UTF-8

control "V-58155" do
  title "The DBMS must maintain the confidentiality and integrity of
information during reception."
  desc  "Information can be either unintentionally or maliciously disclosed or
modified during reception, including, for example, during aggregation, at
protocol transformation points, and during packing/unpacking. These
unauthorized disclosures or modifications compromise the confidentiality or
integrity of the information.

    This requirement applies only to those applications that are either
distributed or can allow access to data nonlocally. Use of this requirement
will be limited to situations where the data owner has a strict requirement for
ensuring data integrity and confidentiality is maintained at every step of the
data transfer and handling process.

    When receiving data, the DBMS, associated applications, and infrastructure
must leverage protection mechanisms.
  "
  desc  "check", "
    Check for the following:

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
  tag "gtitle": "SRG-APP-000442-DB-000379"
  tag "gid": "V-58155"
  tag "rid": "SV-72585r1_rule"
  tag "stig_id": "SRG-APP-000442-DB-000379"
  tag "fix_id": nil
  tag "cci": ["CCI-002422"]
  tag "nist": ["SC-8 (2)", "Rev_4"]

  describe ini(input('couchdb_conf_local')) do
    its('ssl.enable') { should eq 'true' }
  end
end

