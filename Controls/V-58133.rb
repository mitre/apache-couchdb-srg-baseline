# encoding: UTF-8

control 'V-58133' do
  title "The DBMS must disable network functions, ports, protocols, and
services deemed by the organization to be nonsecure, in accord with the Ports,
Protocols, and Services Management (PPSM) guidance."
  desc  "Use of nonsecure network functions, ports, protocols, and services
exposes the system to avoidable threats."
  desc  'rationale', ''
  desc  'check', "
    Review the organization-defined network functions, ports, protocols, and
services deemed by to be nonsecure, in accord with the Ports, Protocols, and
Services Management (PPSM) guidance.

    # find . -name \"default.ini\"\t
    # grep \x91chttpd\x92 section
    # grep \x91port\x92

    If any protocol is prohibited by the PPSM guidance and is enabled, this is
a finding.

  "
  desc  'fix', "Disable nonsecure network functions, ports, protovols, and
servies."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag gid: 'V-58133'
  tag rid: 'SV-72563r1_rule'
  tag stig_id: 'SRG-APP-000383-DB-000364'
  tag fix_id: nil
  tag cci: "CCI-001762
The organization disables organization-defined functions, ports, protocols, and
services within the information system deemed to be unnecessary and/or
nonsecure.
NIST SP 800-53 Revision 4 :: CM-7 (1) (b)

"
  tag nist: 'CM-7 (1) (b)'
end

