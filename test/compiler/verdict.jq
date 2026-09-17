# Judge one `soldb debug-diff` or `soldb profile` JSON report.
#
# A debugger invariant that does not hold fails the test: jq exits with the
# reason. How much of the source the optimizer left attributable is a property
# of the compiler, so it is reported in one verdict line rather than required,
# except with `$strict` "true": then every checkpoint must be reached and every
# profile must attribute gas to source. `$asymmetric` "true" allows the candidate
# to have lost attribution the reference kept, which only a comparison between
# two compilers can explain; the same trace read through two formats cannot.

def report:
  (input_filename // "report")
  | split("/")
  | (.[-2] // "" | sub("\\.tmp$"; "")) + " " + (.[-1] | sub("\\.json$"; ""))
  | ltrimstr(" ");
def fail(reason): error("\(report): \(reason)");
def verdict(text): "\(report): \(text)";
def strict: $strict == "true";
def asymmetric: $asymmetric == "true";

# The only diagnostics an optimizer can cause: a checkpoint whose statement was
# removed or merged, or an execution that no longer touches attributed code.
def lost_checkpoint: capture("^(?<side>reference|candidate): checkpoint (?<location>.+) was not reached$");
def unattributed: capture("^(?<side>reference|candidate) trace has no source steps$");
def lost: (lost_checkpoint // empty), (unattributed // empty | .location = "every source step");

# A coverage difference is explained when the candidate lost that very stop.
def explained_by($candidate_lost):
  "\(.reference.source):\(.reference.line)" as $location
  | .kind == "missing" and any($candidate_lost[]; . == "every source step" or . == $location);

def diff_verdict:
  if .schemaVersion != 1 then fail("unknown report schema \(.schemaVersion)") else . end
  | if .executionEquivalent != true then fail("executions differ: \(.executionDifferences | join("; "))") else . end
  | if .equivalent != (.comparable and .differenceCount == 0) then fail("equivalence is inconsistent with the report") else . end
  | if .differencesTruncated then fail("too many differences to judge") else . end
  | (.diagnostics | map(select([lost] == []))) as $unexplained
  | if $unexplained != [] then fail("inconclusive: \($unexplained | join("; "))") else . end
  | [.diagnostics[] | lost] as $losses
  | ([$losses[] | select(.side == "reference") | .location] | unique) as $reference_lost
  | ([$losses[] | select(.side == "candidate") | .location] | unique) as $candidate_lost
  | ($reference_lost - $candidate_lost) as $reference_only
  | if $reference_only != [] then fail("reference lost \($reference_only | join(", ")) while the candidate kept it") else . end
  | ($candidate_lost - $reference_lost) as $candidate_only
  | if $candidate_only != [] and (asymmetric | not) then fail("candidate lost \($candidate_only | join(", ")) while the reference kept it") else . end
  | (.differences | map(select(explained_by($candidate_only) | not))) as $unexplained_differences
  | if $unexplained_differences != [] then fail("\(.differenceCount) coverage difference(s), first: \($unexplained_differences[0] | tojson)") else . end
  | if $losses == [] then verdict("agree, \(.reference.sourceSteps) source step(s)")
    elif strict then fail("lost \(($reference_lost + $candidate_lost) | unique | join(", "))")
    elif $candidate_only != [] then verdict("candidate lost \($candidate_only | join(", "))")
    else verdict("lost \($reference_lost | join(", "))")
    end;

def profile_verdict:
  .totals as $t
  | if $t.unmappedGas != 0 then fail("\($t.unmappedGas) gas on instructions the artifact does not describe") else . end
  | if $t.programGas <= 0 then fail("no program gas") else . end
  | if $t.programGas != $t.stepGas then fail("program gas \($t.programGas) differs from step gas \($t.stepGas)") else . end
  | if $t.sourceGas + $t.sourcelessGas != $t.programGas then fail("source \($t.sourceGas) + sourceless \($t.sourcelessGas) != program \($t.programGas)") else . end
  | if (([.sourceLines[].gas] | add) // 0) != $t.sourceGas then fail("per-line gas does not add up to the source gas") else . end
  | if $t.sourceGas > 0 then verdict("\($t.sourceGas) of \($t.programGas) gas on \(.sourceLines | length) source line(s)")
    elif strict then fail("no gas attributed to source")
    else verdict("no gas attributed to source")
    end;

if type != "object" then fail("not a JSON report")
elif has("totals") then profile_verdict
elif has("comparable") then diff_verdict
else fail("neither a debug-diff nor a profile report")
end
