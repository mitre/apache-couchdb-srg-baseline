# encoding: UTF-8

control "V-58183" do
  title "When invalid inputs are received, the DBMS must behave in a
predictable and documented manner that reflects organizational and system
objectives."
  desc  "A common vulnerability is unplanned behavior when invalid inputs are
received. This requirement guards against adverse or unintended system behavior
caused by invalid inputs, where information system responses to the invalid
input may be disruptive or cause the system to fail into an unsafe state.

    The behavior will be derived from the organizational and system
requirements and includes, but is not limited to, notification of the
appropriate personnel, creating an audit record, and rejecting invalid input.

    This calls for inspection of application source code, which will require
collaboration with the application developers. It is recognized that in many
cases, the database administrator (DBA) is organizationally separate from the
application developers, and may have limited, if any, access to source code.
Nevertheless, protections of this type are so important to the secure operation
of databases that they must not be ignored. At a minimum, the DBA must attempt
to obtain assurances from the development organization that this issue has been
addressed, and must document what has been discovered.
  "
  desc  "check", "
    Review system documentation to determine how input errors are to be handled
in general and if any special handling is defined for specific circumstances.

    Review the source code for database program objects (stored procedures,
functions, triggers) and application source code to identify how the system
responds to invalid input.

    As database administrator, make a small syntax error:
    Example command:
    GT /_all_dbs
     Verify the syntax error was logged:
     # find . -name \"default.ini\"
        # grep \"file =\" <path to default.ini>
              if line does not exist or is commented out, this is a finding.
     #grep \"level =\" <path to default.ini>
              if line does not exist or is not set to info, this is a finding.


    If it does not implement the documented behavior, this is a finding.
  "
  desc  "fix", "
    Configure CouchDB to generate audit records for all invalid inputs.
    # find . -name \"default.ini\"
    # set level = info
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000447-DB-000393"
  tag "gid": "V-58183"
  tag "rid": "SV-72613r2_rule"
  tag "stig_id": "SRG-APP-000447-DB-000393"
  tag "fix_id": "F-63391r1_fix"
  tag "cci": ["CCI-002754"]
  tag "nist": ["SI-10 (3)", "Rev_4"]


  describe ini(input('couchdb_conf_default')) do
    its('log.level') { should eq 'info'}
  end

end

