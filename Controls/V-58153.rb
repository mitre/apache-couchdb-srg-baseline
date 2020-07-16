# encoding: UTF-8

control 'V-58153' do
  title "The DBMS must maintain the confidentiality and integrity of
information during preparation for transmission."
  desc  "Information can be either unintentionally or maliciously disclosed or
modified during preparation for transmission, including, for example, during
aggregation, at protocol transformation points, and during packing/unpacking.
These unauthorized disclosures or modifications compromise the confidentiality
or integrity of the information.

    Use of this requirement will be limited to situations where the data owner
has a strict requirement for ensuring data integrity and confidentiality is
maintained at every step of the data transfer and handling process.

    When transmitting data, the DBMS, associated applications, and
infrastructure must leverage transmission protection mechanisms.
  "
  desc  'check', "
    Check for the following:

    # find . -name \"local.ini\"
    # grep \"ssl section\"
    # grep \"enable =\"
    If this is not set equal to true, this is a finding.
  "
  desc  'fix', "
    Configure CouchDB to use SSL
    # find . -name \"local.ini\"
    # set \"enable=true\"
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000441-DB-000378"
  tag gid: "V-58153"
  tag rid: "SV-72583r1_rule"
  tag stig_id: "SRG-APP-000441-DB-000378"
  tag fix_id: nil
  tag cci: ["CCI-002420"]
  tag nist: ["SC-8 (2)"]
end

