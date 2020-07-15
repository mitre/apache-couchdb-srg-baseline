# encoding: UTF-8

control 'V-32478' do
  title "The DBMS must map the PKI-authenticated identity to an associated user
account."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.
Once a PKI certificate has been validated, it must be mapped to a DBMS user
account for the authenticated identity to be meaningful to the DBMS and useful
for authorization decisions."
  desc  'rationale', ''
  desc  'check', "
    Review DBMS configuration to verify DBMS user accounts are being mapped
directly to unique identifying information within the validated PKI certificate.

    To check the cn of the certificate, using openssl, do the following:

    # openssl x509 -noout -subject -in client_cert

    If the cn does not match the users listed in CouchDB and no user mapping is
used, this is a finding.

    If user accounts are not being mapped to authenticated identities, this is
a finding.

    If the cn and the username mapping do not match, this is a finding.
  "
  desc  'fix', "Configure CouchDB to map the authenticated identity directly to
CouchDB user account."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000177-DB-000069'
  tag gid: 'V-32478'
  tag rid: 'SV-42815r3_rule'
  tag stig_id: 'SRG-APP-000177-DB-000069'
  tag fix_id: nil
  tag cci: "CCI-000187
The information system, for PKI-based authentication, maps the authenticated
identity to the account of the individual or group.
NIST SP 800-53 :: IA-5 (2)
NIST SP 800-53A :: IA-5 (2).1
NIST SP 800-53 Revision 4 :: IA-5 (2) (c)

"
  tag nist: 'IA-5 (2) (c)'
end

