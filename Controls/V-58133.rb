# encoding: UTF-8

control "V-58133" do
  title "The DBMS must disable network functions, ports, protocols, and
services deemed by the organization to be nonsecure, in accord with the Ports,
Protocols, and Services Management (PPSM) guidance."
  desc  "Use of nonsecure network functions, ports, protocols, and services
exposes the system to avoidable threats."
  desc  "check", "
    Review the organization-defined network functions, ports, protocols, and
services deemed by to be nonsecure, in accord with the Ports, Protocols, and
Services Management (PPSM) guidance.

    # find . -name \"default.ini\"\t
    # grep httpd section
    # grep port

    If any protocol is prohibited by the PPSM guidance and is enabled, this is
a finding.

  "
  desc  "fix", "Disable nonsecure network functions, ports, protovols, and
servies."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000383-DB-000364"
  tag "gid": "V-58133"
  tag "rid": "SV-72563r1_rule"
  tag "stig_id": "SRG-APP-000383-DB-000364"
  tag "fix_id": "F-63341r1_fix"
  tag "cci": ["CCI-001762"]
  tag "nist": ["CM-7 (1) (b)", "Rev_4"]

  describe ini(input('couchdb_conf_default')) do
    its('httpd.port') { should be_in input('authorized_ports') }
  end
end

