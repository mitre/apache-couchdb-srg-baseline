# encoding: UTF-8

control 'V-32375' do
  title "The DBMS must include additional, more detailed, organization-defined
information in the audit records for audit events identified by type, location,
or subject."
  desc  "Information system auditing capability is critical for accurate
forensic analysis. Reconstruction of harmful events or forensic analysis is not
possible if audit records do not contain enough information. To support
analysis, some types of events will need information to be logged that exceeds
the basic requirements of event type, time stamps, location, source, outcome,
and user identity. If additional information is not available, it could
negatively impact forensic investigations into user actions or other malicious
events.

    The organization must determine what additional information is required for
complete analysis of the audited events. The additional information required is
dependent on the type of information (e.g., sensitivity of the data and the
environment within which it resides). At a minimum, the organization must
employ either full-text recording of privileged commands or the individual
identities of users of shared accounts, or both. The organization must maintain
audit trails in sufficient detail to reconstruct events to determine the cause
and impact of compromise.

    Examples of detailed information the organization may require in audit
records are full-text recording of privileged commands or the individual
identities of shared account users.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the system documentation to identify what additional information the
organization has determined to be necessary.
    # find . -name \"default.ini\"
    # grep \"file =\" <path to default.ini>
    if line does not exist or is commented out, this is a finding.
    #grep \"level =\" <path to default.ini>
    if line does not exist or is not set to info, this is a finding.

    If it is not set to produce audit records to include all
organization-defined additional, more detailed information in the audit records
for audit events identified by type, location, or subject, this is a finding.
  "
  desc  'fix', "
    Configure CouchDB audit settings to produce audit records to include all
organization-defined additional, more detailed information in the audit records
for audit events identified by type, location, or subject, this is a finding.
    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000101-DB-000044'
  tag gid: 'V-32375'
  tag rid: 'SV-42712r4_rule'
  tag stig_id: 'SRG-APP-000101-DB-000044'
  tag fix_id: nil
  tag ccii: CCI-000135
  tag nist: 'AU-3 (1)'
end

