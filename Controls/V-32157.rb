# encoding: UTF-8

control "V-32157" do
  title "The DBMS must limit the number of concurrent sessions to an
organization-defined number per user for all accounts and/or account types."
  desc  "Database management includes the ability to control the number of
users and user sessions utilizing a DBMS. Unlimited concurrent connections to
the DBMS could allow a successful Denial of Service (DoS) attack by exhausting
connection resources; and a system can also fail or be degraded by an overload
of legitimate users. Limiting the number of concurrent sessions per user is
helpful in reducing these risks.

    This requirement addresses concurrent session control for a single account.
It does not address concurrent sessions by a single user via multiple system
accounts; and it does not deal with the total number of sessions across all
accounts.

    The capability to limit the number of concurrent sessions per user must be
configured in or added to the DBMS (for example, by use of a logon trigger),
when this is technically feasible. Note that it is not sufficient to limit
sessions via a web server or application server alone, because legitimate users
and adversaries can potentially connect to the DBMS by other means.

    The organization will need to define the maximum number of concurrent
sessions by account type, by account, or a combination thereof. In deciding on
the appropriate number, it is important to consider the work requirements of
the various types of users. For example, 2 might be an acceptable limit for
general users accessing the database via an application; but 10 might be too
few for a database administrator using a database management GUI tool, where
each query tab and navigation pane may count as a separate session.

    (Sessions may also be referred to as connections or logons, which for the
purposes of this requirement are synonyms.)
  "
  desc  "check", "
     Check CouchDB settings and documentation and verify the limit of the
number of concurrent sessions to an organization-defined number per user for
all accounts and/or account types.
    Discuss oraganization-defined number of concurrent sessions per user
account.

    # find . -name \"default.ini\"
    # grep \"max_connections\" <path to default.ini>
    if the max_connections is over the defined amount this is a finding.

    If it is not set to limit the number of concurrent sessions to an
organization-defined number per user for all accounts and/or account types,
this is a finding
  "
  desc  "fix", "
    Configure CouchDB to produce and verify the limit of the number of
concurrent sessions to an organization-defined number per user for all accounts
and/or account types.
    # find . -name \"default.ini\"
    # set \"max_connections\" equal to the organization defined amount.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000001-DB-000031"
  tag "gid": "V-32157"
  tag "rid": "SV-42474r3_rule"
  tag "stig_id": "SRG-APP-000001-DB-000031"
  tag "fix_id": nil
  tag "cci": ["CCI-000054"]
  tag "nist": ["AC-10", "Rev_4"]
end

