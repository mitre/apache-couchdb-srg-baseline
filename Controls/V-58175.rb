# encoding: UTF-8

control "V-58175" do
  title "When updates are applied to the DBMS software, any software components
that have been replaced or made unnecessary must be removed."
  desc  "Previous versions of DBMS components that are not removed from the
information system after updates have been installed may be exploited by
adversaries.

    Some DBMSs' installation tools may remove older versions of software
automatically from the information system. In other cases, manual review and
removal will be required. In planning installations and upgrades, organizations
must include steps (automated, manual, or both) to identify and remove the
outdated modules.

    A transition period may be necessary when both the old and the new software
are required. This should be taken into account in the planning.
  "
  desc  "check", "
    Obtain evidence that software patches are consistently applied to CouchDB
within the time frame defined for each patch.

    To check software installed by packages, as the system administrator, run
the following command:

    # RHEL/CENT Systems
    $ sudo rpm -qa | grep couchdb

    If multiple versions of postgres are installed but are unused, this is a
finding.
  "
  desc  "fix", "Use package managers (RPM or apt-get) for installing CouchDB.
Unused software is removed when updated."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000454-DB-000389"
  tag "gid": "V-58175"
  tag "rid": "SV-72605r1_rule"
  tag "stig_id": "SRG-APP-000454-DB-000389"
  tag "fix_id": nil
  tag "cci": ["CCI-002617"]
  tag "nist": ["SI-2 (6)", "Rev_4"]
end

