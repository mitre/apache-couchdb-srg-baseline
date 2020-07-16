# encoding: UTF-8

control 'V-58169' do
  title "The DBMS must implement cryptographic mechanisms to prevent
unauthorized modification of organization-defined information at rest (to
include, at a minimum, PII and classified information) on organization-defined
information system components."
  desc  "DBMSs handling data requiring \"data at rest\" protections must employ
cryptographic mechanisms to prevent unauthorized disclosure and modification of
the information at rest. These cryptographic mechanisms may be native to the
DBMS or implemented via additional software or operating system/file system
settings, as appropriate to the situation.

    Selection of a cryptographic mechanism is based on the need to protect the
integrity of organizational information. The strength of the mechanism is
commensurate with the security category and/or classification of the
information. Organizations have the flexibility to either encrypt all
information on storage devices (i.e., full disk encryption) or encrypt specific
data structures (e.g., files, records, or fields).

    The decision whether and what to encrypt rests with the data owner and is
also influenced by the physical measures taken to secure the equipment and
media on which the information resides.
  "
  desc  'check', "
    Review the system documentation to determine whether the organization has
defined the information at rest that is to be protected from disclosure, which
must include, at a minimum, PII and classified information.

    CouchDB does not encrypt data at rest other than passwords.

    If no information is identified as requiring such protection, this is not a
finding.

    Review the configuration of CouchDB, operating system/file system, and
additional software as relevant.

    If any of the information defined as requiring cryptographic protection
from modification is not encrypted in a manner that provides the required level
of protection, this is a finding.

    If disk or filesystem requires encryption, ask the system owner, DBA, and
SA to demonstrate filesystem or disk level encryption.

    If this is required and is not found, this is a finding.
  "
  desc  'fix', "Either handled by device/ filesystem level encryption (OS) or
using a 3rd party encryption software"
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000428-DB-000386"
  tag gid: "V-58169"
  tag rid: "SV-72599r1_rule"
  tag stig_id: "SRG-APP-000428-DB-000386"
  tag fix_id: nil
  tag cci: ["CCI-002475"]
  tag nist: ["SC-28 (1)", "Rev_4"]
end

