# encoding: UTF-8

control "V-58149" do
  title "The DBMS must prevent unauthorized and unintended information transfer
via shared system resources."
  desc  "The purpose of this control is to prevent information, including
encrypted representations of information, produced by the actions of a prior
user/role (or the actions of a process acting on behalf of a prior user/role)
from being available to any current user/role (or current process) that obtains
access to a shared system resource (e.g., registers, main memory, secondary
storage) after the resource has been released back to the information system.
Control of information in shared resources is also referred to as object reuse."
  desc  "check", "
    Review CouchDB architecture to find out if and how it protects the private
resources of one process or user (such as working memory, temporary tables,
uncommitted data) from unauthorized access by another user or process.
    Check for the following:

    # find . -name \"local.ini\"
    # grep \"ssl section\"
    # grep \"enable =\"
    If enable is not set to true, this is a finding.
  "
  desc  "fix", "
    Deploy a DBMS capable of effectively protecting the private resources of
one process or user from unauthorized access by another user or process.

    Configure CouchDB to effectively protect the private resources of one
process or user from unauthorized access by another user or process.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000243-DB-000373"
  tag "gid": "V-58149"
  tag "rid": "SV-72579r1_rule"
  tag "stig_id": "SRG-APP-000243-DB-000373"
  tag "fix_id": nil
  tag "cci": ["CCI-001090"]
  tag "nist": ["SC-4", "Rev_4"]

  describe ini(input('couchdb_conf_local')) do
    its('ssl.enable') { should eq 'true' }
  end
end

