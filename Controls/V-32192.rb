# encoding: UTF-8

control 'V-32192' do
  title "The DBMS must integrate with an organization-level
authentication/access mechanism providing account management and automation for
all users, groups, roles, and any other principals."
  desc  "Enterprise environments make account management for applications and
databases challenging and complex. A manual process for account management
functions adds the risk of a potential oversight or other error. Managing
accounts for the same person in multiple places is inefficient and prone to
problems with consistency and synchronization.

    A comprehensive application account management process that includes
automation helps to ensure that accounts designated as requiring attention are
consistently and promptly addressed.

    Examples include, but are not limited to, using automation to take action
on multiple accounts designated as inactive, suspended, or terminated, or by
disabling accounts located in non-centralized account stores, such as multiple
servers. Account management functions can also include: assignment of group or
role membership; identifying account type; specifying user access
authorizations (i.e., privileges); account removal, update, or termination; and
administrative alerts. The use of automated mechanisms can include, for
example: using email or text messaging to notify account managers when users
are terminated or transferred; using the information system to monitor account
usage; and using automated telephone notification to report atypical system
account usage.

    The DBMS must be configured to automatically utilize organization-level
account management functions, and these functions must immediately enforce the
organization's current account policy.

    Automation may be comprised of differing technologies that when placed
together contain an overall mechanism supporting an organization's automated
account management requirements.
  "
  desc  'check', "
     Check CouchDB settings and documentation and verify an organization-level
authentication/access mechanism providing account management and automation for
all users, groups, roles, and any other principals.

    If all accounts are authenticated by the organization-level
authentication/access mechanism, such as LDAP or Kerberos and not by CouchDB,
this is not a finding.

    This would need to be done on a basis to basis situation depending on the
authentication/access mechanism used , if no authentication/access mechanism is
in place this is a finding.

    All records must use an auth-method of gss, sspi, or ldap.

    If there are any records with a different auth-method than gss, sspi, or
ldap, review the system documentation for justification and approval of these
records.

    If there are any records with a different auth-method than gss, sspi, or
ldap, that are not documented and approved, this is a finding.

    If it is not set to an organization-level authentication/access mechanism
providing account management and automation for all users, groups, roles, and
any other principals, this is a finding.
  "
  desc  'fix', "Implement authentication/access mechanisms to use an
auth-method of gss, sspi, or ldap. Or discuss with management other approved
methods."
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000023-DB-000001"
  tag gid: "V-32192"
  tag rid: "SV-42509r3_rule"
  tag stig_id: "SRG-APP-000023-DB-000001"
  tag fix_id: nil
  tag cci: ["CCI-000015"]
  tag nist: ["AC-2 (1)", "Rev_4"]
end

