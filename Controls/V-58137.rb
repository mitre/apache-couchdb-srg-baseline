# encoding: UTF-8

control 'V-58137' do
  title "The DBMS must prohibit the use of cached authenticators after an
organization-defined time period."
  desc  "If cached authentication information is out-of-date, the validity of
the authentication information may be questionable."
  desc  'check', "
     Review system settings to determine whether the organization-defined limit
for cached authentication is implemented.
    Check for the following:

    # find . -name \"local.ini\"

    #grep \x91couch_httpd_auth\x92 section. Verify that the auth_cache_size
variable is set to 50 or has a defined limit.

    If it is not implemented, this is a finding.
  "
  desc  'fix', "
    Modify system settings to implement the organization-defined limit on the
lifetime of cached authenticators.
    # find . -name \"local.ini\"
    # grep \x91couch_httpd_auth\x92 section <local.ini path>
    # Set the \x91auth_cache_size\x92 variable = 50
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000400-DB-000367"
  tag gid: "V-58137"
  tag rid: "SV-72567r1_rule"
  tag stig_id: "SRG-APP-000400-DB-000367"
  tag fix_id: nil
  tag cci: ["CCI-002007"]
  tag nist: ["IA-5 (13)", "Rev_4"]
end

