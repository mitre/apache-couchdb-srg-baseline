# encoding: UTF-8

control 'V-58165' do
  title "The DBMS must maintain the authenticity of communications sessions by
guarding against man-in-the-middle attacks that guess at Session ID values."
  desc  "One class of man-in-the-middle, or session hijacking, attack involves
the adversary guessing at valid session identifiers based on patterns in
identifiers already known.

    The preferred technique for thwarting guesses at Session IDs is the
generation of unique session identifiers using a FIPS 140-2 approved random
number generator.

    However, it is recognized that available DBMS products do not all implement
the preferred technique yet may have other protections against session
hijacking. Therefore, other techniques are acceptable, provided they are
demonstrated to be effective.
  "
  desc  'check', "
     Review DBMS vendor documentation and system behavior (and if necessary,
consult vendor representatives) to determine whether CouchDB can provide
demonstrably effective protection against man-in-the-middle attacks that guess
at session identifier values.

    Review DBMS settings to determine whether protections against
man-in-the-middle attacks that guess at session identifier values are enabled.

    # find . -name \"local.ini\"
    # grep \"ssl section\"
    # grep \"enable =\"
    If this is not set equal to true, this is a finding.
  "
  desc  'fix', "
    Configure CouchDB to use SSL
    # find . -name \"local.ini\"
    # set \"enable=true\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000224-DB-000384'
  tag gid: 'V-58165'
  tag rid: 'SV-72595r1_rule'
  tag stig_id: 'SRG-APP-000224-DB-000384'
  tag fix_id: nil
  tag ccii: CCI-001188
  tag nist: 'SC-23 (3)'
end

