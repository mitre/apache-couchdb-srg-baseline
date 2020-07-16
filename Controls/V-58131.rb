# encoding: UTF-8

control 'V-58131' do
  title "The DBMS must be configured in accordance with the security
configuration settings based on DoD security configuration and implementation
guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs."
  desc  "Configuring the DBMS to implement organization-wide security
implementation guides and security checklists ensures compliance with federal
standards and establishes a common security baseline across DoD that reflects
the most restrictive security posture consistent with operational requirements.

    In addition to this SRG, sources of guidance on security and information
assurance exist. These include NSA configuration guides, CTOs, DTMs, and IAVMs.
The DBMS must be configured in compliance with guidance from all such relevant
sources.
  "
  desc  'rationale', ''
  desc  'check', "
    Review CouchDB documentation and configuration to determine if CouchDB is
configured in accordance with DoD security configuration and implementation
guidance, including STIGs, NSA configuration guides, CTOs, and DTMs and IAVMs.

    If CouchDB is not configured in accordance with security configuration
settings, this is a finding.
  "
  desc  'fix', "Configure CouchDB in accordance with DoD security configuration
and implementation guidance, including STIGs, NSA configuration guides, CTOs,
and DTMs and IAVMs."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-58131'
  tag rid: 'SV-72561r1_rule'
  tag stig_id: 'SRG-APP-000516-DB-000363'
  tag fix_id: nil
  tag ccii: CCI-000366
  tag nist: 'CM-6 b'
end

