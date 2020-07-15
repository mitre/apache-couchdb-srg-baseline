# encoding: UTF-8

control 'V-58039' do
  title "The DBMS must associate organization-defined types of security labels
having organization-defined security label values with information in process."
  desc  "Without the association of security labels to information, there is no
basis for the DBMS to make security-related access-control decisions.

    Security labels are abstractions representing the basic properties or
characteristics of an entity (e.g., subjects and objects) with respect to
safeguarding information.

    These labels are typically associated with internal data structures (e.g.,
tables, rows) within the database and are used to enable the implementation of
access control and flow control policies, reflect special dissemination,
handling or distribution instructions, or support other aspects of the
information security policy.

    One example includes marking data as classified or FOUO. These security
labels may be assigned manually or during data processing, but, either way, it
is imperative these assignments are maintained while the data is in storage. If
the security labels are lost when the data is stored, there is the risk of a
data compromise.

    The mechanism used to support security labeling may be a feature of the
DBMS product, a third-party product, or custom application code.
  "
  desc  'rationale', ''
  desc  'check', "
    If security labeling is not required, this is not a finding.

    Review organization-defined types of security labels.

    If security labeling requirements have been specified, but the security
labeling is not implemented or does not reliably maintain labels on information
in process, this is a finding.
  "
  desc  'fix', "
    If security labeling is not defined by the organizaiton, but should be,
this should be implemented and recorded by organization in their defined plan.

    If security labeling is defined, but not present, it must be added.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000313-DB-000309'
  tag gid: 'V-58039'
  tag rid: 'SV-72469r1_rule'
  tag stig_id: 'SRG-APP-000313-DB-000309'
  tag fix_id: nil
  tag cci: "CCI-002263
The organization provides the means to associate organization-defined types of
security attributes having organization-defined security attribute values with
information in process.
NIST SP 800-53 Revision 4 :: AC-16 a

"
  tag nist: 'AC-16 a'
end

