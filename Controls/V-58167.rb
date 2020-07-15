# encoding: UTF-8

control 'V-58167' do
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
  desc  'rationale', ''
  desc  'check', "
    Check for the following:
    # find . -name \"local.ini\"

    #grep \x91ssl\x92 section
    Verify \"enabled = true\"
    #grep \"cert_file = /etc/couchdb/cert/couchdb.pem\"
    Verify for certificates issued by DoD PKI or DoD-approved PKI Certification
Authorities (CAs)

    If CouchDB will accept non-DoD approved PKI end-entity certificates, this
is a finding
  "
  desc  'fix', "Revoke trust in any certificates not issued by a DoD-approved
certificate authority. Configure CouchDB to accept only DoD and DoD-approved
PKI end-entity certificates."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000427-DB-000385'
  tag gid: 'V-58167'
  tag rid: 'SV-72597r1_rule'
  tag stig_id: 'SRG-APP-000427-DB-000385'
  tag fix_id: nil
  tag cci: "CCI-002470
The information system only allows the use of organization-defined certificate
authorities for verification of the establishment of protected sessions.
NIST SP 800-53 Revision 4 :: SC-23 (5)

"
  tag nist: 'SC-23 (5)'
end

