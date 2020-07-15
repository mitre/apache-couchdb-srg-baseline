# encoding: UTF-8

control 'V-32526' do
  title 'The DBMS must recognize only system-generated session identifiers.'
  desc  "DBMSs utilize sessions and session identifiers to control application
behavior and user access. If an attacker can guess the session identifier or
can inject or manually insert session information, the session may be
compromised.

    This requirement focuses on communications protection for the DBMS session
rather than for the network packet. The intent of this control is to establish
grounds for confidence at each end of a communications session in the ongoing
identity of the other party and in the validity of the information being
transmitted.

    The DBMS must recognize only system-generated session identifiers. If an
attacker were able to generate a session with a non-system-generated session
identifier and have it recognized by the system, the attacker could gain access
to the system without passing through access controls designed to limit
database sessions to authorized users.
  "
  desc  'rationale', ''
  desc  'check', "
     Review the CouchDB settings and vendor documentation to determine whether
CouchDB recognizes session identifiers that are not system-generated.

    If CouchDB recognizes session identifiers that are not system generated,
this is a finding.
  "
  desc  'fix', "Utilize a CouchDB product that only recognizes session
identifiers that are system-generated."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000223-DB-000168'
  tag gid: 'V-32526'
  tag rid: 'SV-42863r2_rule'
  tag stig_id: 'SRG-APP-000223-DB-000168'
  tag fix_id: nil
  tag cci: "CCI-001664
The information system recognizes only session identifiers that are
system-generated.
NIST SP 800-53 :: SC-23 (3)
NIST SP 800-53A :: SC-23 (3).1 (ii)
NIST SP 800-53 Revision 4 :: SC-23 (3)

"
  tag nist: 'SC-23 (3)'
end

