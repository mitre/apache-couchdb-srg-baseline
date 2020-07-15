# encoding: UTF-8

control 'V-32203' do
  title "The DBMS must enforce approved authorizations for logical access to
information and system resources in accordance with applicable access control
policies."
  desc  "Authentication with a DoD-approved PKI certificate does not
necessarily imply authorization to access the DBMS.  To mitigate the risk of
unauthorized access to sensitive information by entities that have been issued
certificates by DoD-approved PKIs, all DoD systems, including databases, must
be properly configured to implement access control policies.

    Successful authentication must not automatically give an entity access to
an asset or security boundary. Authorization procedures and controls must be
implemented to ensure each authenticated entity also has a validated and
current authorization. Authorization is the process of determining whether an
entity, once authenticated, is permitted to access a specific asset.
Information systems use access control policies and enforcement mechanisms to
implement this requirement.

    Access control policies include identity-based policies, role-based
policies, and attribute-based policies. Access enforcement mechanisms include
access control lists, access control matrices, and cryptography. These policies
and mechanisms must be employed by the application to control access between
users (or processes acting on behalf of users) and objects (e.g., devices,
files, records, processes, programs, and domains) in the information system.

    This requirement is applicable to access control enforcement applications,
a category that includes database management systems.  If the DBMS does not
follow applicable policy when approving access, it may be in conflict with
networks or other applications in the information system. This may result in
users either gaining or being denied access inappropriately and in conflict
with applicable policy.
  "
  desc  'rationale', ''
  desc  'check', "
    From the system security plan or equivalent documentation, determine the
appropriate permissions on database objects for each kind (group role) of user.
If this documentation is missing, this is a finding.

    Check the permissions of all databases.
    #GET /{db}/_security
    Review all roles and their associated privileges. If any roles' privileges
exceed those documented, this is a finding.


    Review all entries and their associated authentication methods. If any
entries do not have their documented authentication requirements, this is a
finding.
  "
  desc  'fix', "
    Use the following command to set security objects correctly:

    # PUT /{db}/_security

    Example request:
    shell> curl http://localhost:5984/pineapple/_security -X PUT -H
'content-type: application/json' -H 'accept: application/json' -d
'{\"admins\":{\"names\":[\"superuser\"],\"roles\":[\"admins\"]},\"members\":{\"names\":
[\"user1\",\"user2\"],\"roles\": [\"developers\"]}}'
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag gid: 'V-32203'
  tag rid: 'SV-42520r3_rule'
  tag stig_id: 'SRG-APP-000033-DB-000084'
  tag fix_id: nil
  tag cci: "CCI-000213
The information system enforces approved authorizations for logical access to
information and system resources in accordance with applicable access control
policies.
NIST SP 800-53 :: AC-3
NIST SP 800-53A :: AC-3.1
NIST SP 800-53 Revision 4 :: AC-3

"
  tag nist: 'AC-3'
end

