# encoding: UTF-8

control 'V-58053' do
  title "The DBMS must allocate audit record storage capacity in accordance
with organization-defined audit record storage requirements."
  desc  "In order to ensure sufficient storage capacity for the audit logs, the
DBMS must be able to allocate audit record storage capacity. Although another
requirement (SRG-APP-000515-DB-000318) mandates that audit data be off-loaded
to a centralized log management system, it remains necessary to provide space
on the database server to serve as a buffer against outages and capacity limits
of the off-loading mechanism.

    The task of allocating audit record storage capacity is usually performed
during initial installation of the DBMS and is closely associated with the DBA
and system administrator roles. The DBA or system administrator will usually
coordinate the allocation of physical drive space with the application
owner/installer and the application will prompt the installer to provide the
capacity information, the physical location of the disk, or both.

    In determining the capacity requirements, consider such factors as: total
number of users; expected number of concurrent users during busy periods;
number and type of events being monitored; types and amounts of data being
captured; the frequency/speed with which audit records are off-loaded to the
central log management system; and any limitations that exist on the DBMS's
ability to reuse the space formerly occupied by off-loaded records.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the organization=defined audit record storage requirements.

    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    # df <path to log file>

    If disk space returned is lower than organization-defined storage
requirements, this is a finding.
  "
  desc  'fix', "Configure CouchDB to allocate audit record storage capacity in
accordance with organization-defined audit record storage requirements."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000357-DB-000316'
  tag gid: 'V-58053'
  tag rid: 'SV-72483r1_rule'
  tag stig_id: 'SRG-APP-000357-DB-000316'
  tag fix_id: nil
  tag cci: "CCI-001849
The organization allocates audit record storage capacity in accordance with
organization-defined audit record storage requirements.
NIST SP 800-53 Revision 4 :: AU-4

"
  tag nist: 'AU-4'
end

