# encoding: UTF-8

control "V-58125" do
  title "The DBMS must enforce access restrictions associated with changes to
the configuration of the DBMS or database(s)."
  desc  "Failure to provide logical access restrictions associated with changes
to configuration may have significant effects on the overall security of the
system.

    When dealing with access restrictions pertaining to change control, it
should be noted that any changes to the hardware, software, and/or firmware
components of the information system can potentially have significant effects
on the overall security of the system.

    Accordingly, only qualified and authorized individuals should be allowed to
obtain access to system components for the purposes of initiating changes,
including upgrades and modifications.
  "
  desc  "check", "
    To list the privileges, as the database administrator, run the following:
     #GET /db/_security

    If the privileges are exceed what user and groups should have, this is a
finding.
  "
  desc  "fix", "
    Use the following command to set privileges correctly:

    # PUT /{db}/_security

    Example request:
    shell> curl http://localhost:5984/pineapple/_security -X PUT -H
'content-type: application/json' -H 'accept: application/json' -d
'{\"admins\":{\"names\":[\"superuser\"],\"roles\":[\"admins\"]},\"members\":{\"names\":
[\"user1\",\"user2\"],\"roles\": [\"developers\"]}}'
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000380-DB-000360"
  tag "gid": "V-58125"
  tag "rid": "SV-72555r1_rule"
  tag "stig_id": "SRG-APP-000380-DB-000360"
  tag "fix_id": nil
  tag "cci": ["CCI-001813"]
  tag "nist": ["CM-5 (1)", "Rev_4"]
end

