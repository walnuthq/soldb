//! A Foundry test run end to end: the session Foundry's soldb frontend opens, over a trace
//! with the test contract's deployment, `setUp()`, and `test_Increment()` as three
//! top-level calls (`test/fixtures/foundry-unit-test`).
//!
//! NOTE: The CLI cannot open a saved trace in the REPL yet, so this drives `Session` directly.
//! Once `soldb trace` or `soldb replay` accepts a trace file, this can move to a lit test
//! next to `test/dap/foundry-multi-root.test`.

use std::path::{Path, PathBuf};

use soldb_core::TransactionTrace;
use soldb_debugger::ContractDebugInfo;
use soldb_ethdebug::{load_contract_mapping, load_debug_program, SourceMapEnvironment};
use soldb_repl::{DebuggerCommand, DebuggerState, Renderer, Session};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/fixtures/foundry-unit-test")
}

/// The session as Foundry opens it: the trace, then each contract's debug info.
fn session() -> Session {
    let fixture = fixture();
    let trace = serde_json::from_str::<TransactionTrace>(
        &std::fs::read_to_string(fixture.join("trace.json")).expect("trace"),
    )
    .expect("trace json");
    let contracts = load_contract_mapping(&fixture.join("contracts.json"))
        .expect("mapping")
        .into_iter()
        .map(|mapping| {
            let program = load_debug_program(
                &mapping.debug_dir,
                &mapping.name,
                SourceMapEnvironment::Runtime,
            )
            .expect("debug program")
            .expect("a program for every mapped contract");
            let name = program.info.contract_name.clone();
            ContractDebugInfo::new(
                Some(&mapping.address),
                &name,
                program.info,
                program.source_contents,
            )
        })
        .collect();
    let mut state = DebuggerState::new();
    state
        .load_trace(trace)
        .expect("top-level calls must start at different steps");
    state.attach_debug_info(contracts);
    Session::new(state)
}

/// The initial stop, then each command with what it printed.
fn transcript(commands: &[&str]) -> String {
    let mut session = session();
    let renderer = Renderer::new(false);
    let mut text = session
        .initial_stop()
        .iter()
        .map(|output| renderer.render(output))
        .collect::<String>();
    for command in commands {
        text.push_str(&format!("soldb> {command}\n"));
        for output in session.execute(DebuggerCommand::parse(command)) {
            text.push_str(&renderer.render(&output));
        }
    }
    text
}

#[test]
fn steps_from_the_deployment_through_set_up_into_the_test() {
    assert_eq!(
        transcript(&["bt", "next", "bt", "next", "next", "next", "next", "bt", "next", "bt"]),
        "\
test/Counter.t.sol:6  (step 0/795, pc 0, PUSH1, gas 306341)
    6 | contract CounterTest {
soldb> bt
#0  [deployment] CounterTest at test/Counter.t.sol:6  step 0, PC 0
soldb> next
test/Counter.t.sol:9 in setUp  (step 41/795, pc 56, JUMPDEST, gas 174314)
    9 |     function setUp() public {
soldb> bt
#0  setUp at test/Counter.t.sol:9  step 41, PC 56
#1  [setup] CounterTest at test/Counter.t.sol:6  step 40, PC 40
soldb> next
test/Counter.t.sol:10 in setUp  (step 46/795, pc 77, PUSH1, gas 174298)
   10 |         counter = new Counter();
soldb> next
test/Counter.t.sol:11 in setUp  (step 115/795, pc 177, PUSH0, gas 23558)
   11 |         counter.setNumber(1);
soldb> next
test/Counter.t.sol:9 in setUp  (step 374/795, pc 312, JUMP, gas 326)
    9 |     function setUp() public {
soldb> next
test/Counter.t.sol:6  (step 377/795, pc 0, PUSH1, gas 11500)
    6 | contract CounterTest {
soldb> bt
#0  [execution] CounterTest at test/Counter.t.sol:6  step 377, PC 0
soldb> next
test/Counter.t.sol:14 in test_Increment  (step 406/795, pc 66, JUMPDEST, gas 11382)
   14 |     function test_Increment() public {
soldb> bt
#0  test_Increment at test/Counter.t.sol:14  step 406, PC 66
#1  [execution] CounterTest at test/Counter.t.sol:6  step 405, PC 51
"
    );
}

#[test]
fn a_breakpoint_in_the_test_and_each_calls_own_calldata() {
    assert_eq!(
        transcript(&[
            "next",
            "next",
            "calldata",
            "break test/Counter.t.sol:16",
            "continue",
            "bt",
            "calldata",
        ]),
        "\
test/Counter.t.sol:6  (step 0/795, pc 0, PUSH1, gas 306341)
    6 | contract CounterTest {
soldb> next
test/Counter.t.sol:9 in setUp  (step 41/795, pc 56, JUMPDEST, gas 174314)
    9 |     function setUp() public {
soldb> next
test/Counter.t.sol:10 in setUp  (step 46/795, pc 77, PUSH1, gas 174298)
   10 |         counter = new Counter();
soldb> calldata
Calldata: 4 bytes
0x0a9254e4
soldb> break test/Counter.t.sol:16
Breakpoint #1 set at test/Counter.t.sol:16
soldb> continue
Breakpoint #1 hit at step 559, test/Counter.t.sol:16
test/Counter.t.sol:16 in test_Increment  (step 559/795, pc 437, PUSH1, gas 1077)
   16 |         require(counter.number() == 2, \"not incremented\");
soldb> bt
#0  test_Increment at test/Counter.t.sol:16  step 559, PC 437
#1  [execution] CounterTest at test/Counter.t.sol:6  step 405, PC 51
soldb> calldata
Calldata: 4 bytes
0x4820a105
"
    );
}
