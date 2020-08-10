# encoding: UTF-8

control "V-58067" do
  title "The DBMS must provide the means for individuals in authorized roles to
change the auditing to be performed on all application components, based on all
selectable event criteria within organization-defined time thresholds."
  desc  "If authorized individuals do not have the ability to modify auditing
parameters in response to a changing threat environment, the organization may
not be able to effectively respond, and important forensic information may be
lost.

    This requirement enables organizations to extend or limit auditing as
necessary to meet organizational requirements. Auditing that is limited to
conserve information system resources may be extended to address certain threat
situations. In addition, auditing may be limited to a specific set of events to
facilitate audit reduction, analysis, and reporting. Organizations can
establish time thresholds in which audit actions are changed, for example, near
real time, within minutes, or within hours.
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
  tag "gtitle": "SRG-APP-000353-DB-000324"
  tag "gid": "V-58067"
  tag "rid": "SV-72497r1_rule"
  tag "stig_id": "SRG-APP-000353-DB-000324"
  tag "fix_id": nil
  tag "cci": ["CCI-001914"]
  tag "nist": ["AU-12 (3)", "Rev_4"]
end

