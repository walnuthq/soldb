# SolDB REPL Commands

This document lists the commands available inside the SolDB interactive debugger REPL.

Start the REPL with one of:

```console
soldb trace <tx_hash> --interactive
soldb simulate <contract_address> <function_signature> [args...] --from <sender> --interactive
soldb run <bytecode> [<function_signature> [args...]] --interactive
```

Pass `--ethdebug-dir <address>:<contract>:<dir>` to load the compiler's debug metadata.
Source-level stepping, line and function breakpoints, `list`, `vars`, and `print` need it;
everything else works on the bare trace. ETHDebug artifacts and the legacy `combined.json`
source maps of pre-ETHDebug compilers both serve: lines, functions, and frames come from
the map and the source text either way. Only *local* variables need ETHDebug, because
their locations exist nowhere else; state variables are read from the storage layout
`solc --storage-layout` writes, which pre-ETHDebug compilers emit as well.

The prompt is:

```text
soldb>
```

## What a Stop Shows

Every stop prints the step, its program counter, opcode, and remaining gas. In source mode
(the default) it also prints where the step is in the source and the line's text:

```text
Step 156/1071 | PC 1872 | PUSH2 | gas 978188
TestContract.sol:28 in increment
   28 |         counter += amount;
```

Compilers attach helper code they generate (checked arithmetic, `require` reverts, storage
updates) to the contract as a whole rather than to a line. The debugger attributes such a
step to the statement that was executing and marks it:

```text
TestContract.sol:28 in increment  (compiler-generated code for this line)
```

In assembly mode (`mode asm`) the stop prints the EVM stack instead of the source.

## Stepping

A trace is a complete recording, so every command below is a search over it. Nothing is
re-executed, and a breakpoint anywhere in the code a command runs through stops it early.

### `next`

Aliases: `n`

Run to the start of the next source line in the current function or a caller, stepping
over calls: internal Solidity calls as well as calls into other contracts.

```text
soldb> next
```

From the dispatcher, where no function is executing yet, `next` enters the function the
transaction calls. Without debug metadata `next` moves one EVM instruction.

### `step`

Aliases: `s`

Run to the start of the next source line anywhere, entering calls. A call into a contract
without debug metadata stops at its first step and says that it has no source.

```text
soldb> step
```

### `nexti`

Aliases: `ni`, `stepi`, `si`

Advance one EVM instruction.

### `finish`

Aliases: `fin`

Run until the current frame returns to its caller: the end of the current internal
function, or of the current external call. At the root, `finish` runs to the end of the
trace.

### `continue`

Aliases: `c`

Run to the next breakpoint, or to the end of the trace.

## Reverse Stepping

Each stepping command has a reverse form that moves backward through the recording from any
step, including the middle of a transaction.

| command | aliases | moves to |
| --- | --- | --- |
| `reverse-next` | `rnext`, `rn` | the start of the previous line in this frame or a caller, skipping calls it made; from the middle of a line, the start of that line |
| `reverse-step` | `rstep`, `rs` | the start of the previous line anywhere, entering calls |
| `reverse-nexti` | `rnexti`, `rni`, `reverse-stepi`, `rsi`, `back` | the previous EVM instruction |
| `reverse-finish` | `rfinish`, `rfin` | the step in the caller that entered the current frame |
| `reverse-continue` | `rcontinue`, `rc` | the nearest earlier breakpoint, or the first step |

```text
soldb> break 42
soldb> reverse-continue
Breakpoint #1 hit at step 17, PC 42
soldb> rc
Start of trace at step 0
```

The DAP server exposes the same capability as `stepBack` and `reverseContinue`, so an
editor's step-back buttons work on a trace too.

## Navigation

### `goto <step>`

Jump to a trace step index.

```text
soldb> goto 42
```

If the requested step is outside the loaded trace, SolDB prints the valid maximum step.

## Breakpoints

A breakpoint is a predicate on a step. Setting one prints its number; `continue` and
`reverse-continue` stop at the first step that satisfies any breakpoint, and so do `next`,
`step`, and `finish` when they run through one.

### `break <pc>`

Aliases: `b <pc>`

Stop at an EVM program counter. `<pc>` accepts decimal or hex.

```text
soldb> break 141
soldb> b 0x8d
```

### `break <file>:<line>`

Aliases: `b <file>:<line>`

Stop when execution enters a source line. The file may be given as a name, a trailing part
of its path, or the whole path.

A line breakpoint hits once each time the line is entered, not on every instruction the
line compiles to, and not when a call made from the line returns into the middle of it. A
line inside a multi-line statement resolves to the statement: `break Counter.sol:12` on the
second line of a call spanning lines 11 to 13 reports `Counter.sol:11 (the statement
containing line 12)`.

Among the instructions whose ETHDebug span touches the line, SolDB prefers those whose span
*begins* on it. Compilers attach a whole-contract span to the dispatcher and to generated
helpers, and that span technically contains every line, so without this preference every
source breakpoint would resolve to the start of the contract.

```text
soldb> break Counter.sol:7
soldb> b contracts/Counter.sol:7
```

### `break line <line>`

Aliases: `b line <line>`

Set a source-line breakpoint without naming a file. This works only when the loaded debug
metadata has a single source file; otherwise SolDB asks for the `<file>:<line>` form.

### `break <function>`

Aliases: `b <function>`, `b <Contract>.<function>`

Stop when a function is entered, each time it is entered. Functions come from the source
text: `function`, `modifier`, `constructor`, `fallback`, and `receive` declarations. Qualify
the name with the contract when several loaded contracts declare it.

```text
soldb> break increment3
Breakpoint #1 set at function TestContract.increment3 at TestContract.sol:54
```

### `break storage <slot>`

Stop at an `SSTORE` to a storage slot, given in decimal or hex.

```text
soldb> break storage 0
Breakpoint #1 set at storage slot 0x0
soldb> continue
Breakpoint #1 hit at step 296, storage slot 0x0, PC 1520
```

### `break revert`

Stop at a `REVERT`, or at any step the backend marked as failing.

### `break call [<address>]`

Stop at a `CALL`, `CALLCODE`, `DELEGATECALL`, or `STATICCALL`: any of them, or one whose
target is the given address.

### `break op <OPCODE>`

Stop at every execution of one opcode, for example `break op SSTORE` or `break op LOG1`.

### `break <target> if <condition>`

Stop at the target only when the condition holds there.

```text
soldb> break TestContract.sol:44 if counter >= 4
Breakpoint #1 set at TestContract.sol:44 if counter >= 4
soldb> continue
Breakpoint #1 hit at step 354, TestContract.sol:44 if counter >= 4, PC 1714
soldb> break increment2 if amount == 4
soldb> break op SSTORE if depth == 1 && gas > 0
```

A condition compares values the debugger can read at that step:

- state variables through the storage layout, including `balances[0xabc…]`,
  `items[2]`, and `config.limit`;
- the arguments of the frame being entered, by name, when the trace has proven them
  (see [`backtrace`](#backtrace));
- `pc`, `gas`, `depth`, and `step` as numbers, and `op` as text.

Operands are those names, decimal or `0x` numbers, `true`, `false`, and quoted strings.
Comparisons are `==`, `!=`, `<`, `<=`, `>`, and `>=`; a bare name holds when it is true or
non-zero. Terms join with `&&` and `||`, which is as far as it goes: there is no
arithmetic and no calls, because evaluating those would mean executing Solidity, and the
debugger only reads the recording.

Signed types compare as signed. A condition is checked only at steps the target already
matched, so it costs nothing on the steps a movement passes through.

A condition that cannot be read at all — a slot the transaction never touched, a name
nothing defines — does not stop, and the debugger says why rather than leaving a
breakpoint that silently never fires:

```text
soldb> break TestContract.sol:44 if nosuch > 1
soldb> continue
End of trace at step 1071
A breakpoint condition never held: `nosuch > 1` could not be evaluated: no state variable named `nosuch` in the storage layout
```

The DAP server takes the editor's own breakpoint conditions through the same path, so a
condition typed in an editor behaves exactly as one typed here.

### `clear <target>`

Remove the breakpoint that was set with the same target: `clear 141`, `clear Counter.sol:7`,
`clear line 7`, `clear increment`, `clear storage 0`, `clear revert`, `clear call`,
`clear op SSTORE`.

### `delete <n>`

Aliases: `d <n>`

Remove breakpoint number `n`, as printed when it was set or by `info breakpoints`.

### `info breakpoints`

Aliases: `info break`, `i b`

List every breakpoint with its number.

```text
soldb> info breakpoints
#1 TestContract.sol:30
#2 storage slot 0x0
```

## Inspection

### `backtrace`

Aliases: `bt`, `where`

Print the call frames at the current step, innermost first. A frame is an external call or
an internal Solidity function; each shows its function (or, without source, the contract or
address executing), where it is, and the step and program counter it sits at. Frames above
the innermost one show the call site.

```text
soldb> bt
#0  increment3 at TestContract.sol:54  step 596, PC 1522
#1  increment2(amount = 4) at TestContract.sol:48  step 595, PC 1770
#2  increment(amount = 4) at TestContract.sol:30  step 300, PC 1902
#3  TestContract at TestContract.sol:8  step 103, PC 824
```

A frame shows the arguments it was entered with when the trace has shown where its
compiler leaves them. These values are read off the stack, not reported by the compiler,
and the first backtrace that shows any says so once. When solc emits ETHDebug variable
locations, those will replace this reading. Solidity's two code generators disagree — the legacy pipeline pushes
parameters left to right and via-IR right to left — and nothing in the artifacts says which
produced the code, so SolDB proves it instead of assuming: the first function entered in a
frame whose calldata is known is the function that calldata selected, so comparing the
calldata words with the words on the entry stack settles both whether the parameters are
there and which end the first one is at. What that proves for a contract is used for every
frame of it.

Three things follow. A frame of more than one parameter shows nothing until a call with at
least two arguments has proven the order, which is why `increment3` above is bare. A
contract whose public functions are entered through a dispatcher wrapper that has not
decoded the arguments yet — how solc's legacy pipeline compiles them — shows nothing at
all, because a frame that disagrees disproves the whole contract. And only value-type
parameters are shown, since each is exactly one word; a `string`, `bytes`, array, or struct
parameter is a pointer whose width depends on where it lives, so a function taking one
reports no arguments rather than a memory offset dressed up as a number.

Internal frames come from three sources, in this order of trust. Jump markers when the
artifact carries them: legacy source maps mark every jump into and out of a function, and
ETHDebug's `invoke` and `return` context does the same once a compiler emits it. The entry
point of each parsed function: a jump onto it is a call even when that function is already
active, so recursion and mutual recursion count, and the return address is read off the
stack at the call, so the jump that lands there is the return even when it lands in the
same function. Otherwise, the function a span lands in: one that is not on the stack is
entered, one that is on the stack is returned to.

### `list`

Aliases: `l`

Print five lines of source on each side of the current step's line, marking the current one.

```text
soldb> list
TestContract.sol:32
      27 |         uint256 oldValue = counter;
      28 |         counter += amount;
      29 |
      30 |         increment2(amount);
      31 |
=>    32 |         emit CounterIncremented(counter);
      33 |     }
```

### `stack`

Print the EVM stack at the current step.

### `memory [offset [length]]`

Print memory at the current step in 32-byte words: all of it, or `length` bytes from
`offset`. Both accept decimal or hex.

```text
soldb> memory 0x40 32
Memory: 96 bytes, showing bytes 64..96
0x0040: 0000000000000000000000000000000000000000000000000000000000000080
```

### `storage`

Aliases: `info storage`

Print every storage slot whose value is known at the current step, for the account the
step's frame writes to — the executing contract, or the caller under a `DELEGATECALL`.

```text
soldb> storage
Storage: of 0x5fbdb2315678afecb367f032d93f642f64180aa3
  0x0 = 0x4
```

A backend records a slot at the `SLOAD` or `SSTORE` that touches it, so this is every
slot the transaction has read or written so far, not a full storage dump: SolDB keeps no
chain state and does not ask a node for slots the trace never mentioned. Slots written at
this step are marked with their previous value. Says so when the backend captured no
storage at all.

### `calldata`

Print the calldata of the current frame: the transaction input at the root, or the
recorded call's input in a nested frame when the backend recorded calls.

## Variables

Both commands need the session to be started with
`--ethdebug-dir <address>:<contract>:<dir>`, and they read two things from it.

*Local* variables come from the ETHDebug variable information for the current program
counter, shared with the DAP server's variables view. A compiler only reports them if it
emits `context.variables` in its ETHDebug output, and no compiler release does yet. When
the loaded artifact carries no variable locations at all, `vars` and `print` say that,
rather than reporting an empty scope:

```text
soldb> vars
Variables: this artifact carries no ETHDebug variable locations, so locals cannot be shown; the compiler that produced it does not emit them yet
```

That is a limitation of the debug info, not of the lookup, and it is worth telling apart
from `no variables in scope at PC …`, which means the compiler did describe variables and
none of them is live here.

*State* variables come from the storage layout, the `<Contract>_storage.json` (or the
`storage-layout` entry of a legacy `combined.json`) that `solc --storage-layout` writes.
`soldb compile` and the test harness pass that flag; for a directory compiled without it,
SolDB says so instead of guessing where a variable lives. The slot arithmetic behind
mappings, arrays, and structs is Solidity's own rule, so the values are read, never
inferred.

### `vars`

Aliases: `locals`

Print every source variable ETHDebug reports as live at the current program counter, with
its declared type, decoded value, and the location the value was read from, followed by
every state variable of the contract with the slot it lives in.

```text
soldb> vars
uint256 amount = 5 [stack+2]
uint256 oldValue = 0 [stack+1]
State:
uint256 counter = 4 [slot 0x0]
mapping(address => uint256) balances = <mapping; index it with [key]> [slot 0x1]
```

A value shown as `<unavailable>` means the backend did not capture the stack, memory, or
storage the variable lives in, not that the variable is unset.

A state variable the transaction never touched is read from the node when the session has
one, and the value says where it came from:

```text
uint256 counter = 41 [slot 0x0, from the chain at block 21000000, before this transaction's block]
```

For a traced transaction that is the state at the end of the parent block, which is what
the transaction started from unless a transaction earlier in the same block wrote the slot;
for a simulated call it is the block the call ran on top of. Each slot is read once and
remembered. Without a node — `soldb run`, or `soldb replay` from a file — there is nothing
to ask, and the value reads `<unknown: slot … has not been read or written yet>`: the trace
does not say what is there, and it does not mean zero.

### `print <variable>`

Aliases: `p <variable>`

Print one variable by name: a local ETHDebug reports at this program counter, or a state
variable, including one place inside it.

```text
soldb> print amount
uint256 amount = 5 [stack+2]
soldb> print counter
uint256 counter = 4 [slot 0x0]
soldb> print balances[0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266]
uint256 balances[0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266] = 25 [slot 0xa3c1…9502]
soldb> print config.limit
uint256 config.limit = 99 [slot 0x6]
soldb> print items[1]
uint256 items[1] = 9 [slot 0x8a35…d19c]
```

A path is a state variable name followed by any number of `[key]`, `[index]`, and
`.member` steps: mapping keys are values (`0xabc…`, `42`, `true`, `"name"` for a string
key), array indices are numbers, and members are declared names. Indexing a mapping or an
array reports the entry's own slot, so the value can be checked against `storage`.

If the name is not live at the current program counter and names no state variable, SolDB
says so and names the PC it looked at, so you can step to a point where the variable is in
scope.

## Metadata

### `info resources`

Print the ETHDebug resources loaded for the active debug session.

```text
soldb> info resources
```

Use JSON output when scripting the REPL:

```text
soldb> info resources --json
```

This command requires the interactive session to be started with ETHDebug metadata.

## Display Mode

### `mode`

Print the current display mode.

### `mode source`

Aliases: `mode src`

Show the source location and line at each stop (the default).

### `mode asm`

Aliases: `mode assembly`

Show the EVM stack at each stop instead of the source.

## Help

### `help`

Print the REPL command summary.

```text
soldb> help
Stepping: next (n), step (s), nexti (ni), finish (fin), continue (c), goto <step>
Reverse:  reverse-next (rn), reverse-step (rs), reverse-nexti (back), reverse-finish (rfin), reverse-continue (rc)
Break:    break <pc>|<file>:<line>|line <line>|<function>|storage <slot>|revert|call [<address>]|op <OPCODE>
          clear <target>, delete <n>, info breakpoints
Inspect:  backtrace (bt), list (l), vars, print <variable>|<state>[<key>], stack, memory [offset [length]], storage, calldata
Other:    info resources [--json], mode source|asm, help <command>, quit
```

`help <command>` prints the details for a command group: `help next`, `help break`,
`help backtrace`, `help vars`, `help info`, `help mode`.

## Exit

### `quit`

Aliases: `exit`, `q`

Exit the interactive debugger.

## Example Session

```text
soldb> break TestContract.sol:30
Breakpoint #1 set at TestContract.sol:30
soldb> continue
Breakpoint #1 hit at step 299, TestContract.sol:30, PC 1899
Step 299/1071 | PC 1899 | PUSH2 | gas 955476
TestContract.sol:30 in increment
   30 |         increment2(amount);
soldb> step
Step 301/1071 | PC 1678 | JUMPDEST | gas 955465
TestContract.sol:39 in increment2
   39 |     function increment2(uint256 amount) public {
soldb> finish
Step 962/1071 | PC 1903 | JUMPDEST | gas 950160
TestContract.sol:30 in increment
   30 |         increment2(amount);
soldb> next
Step 963/1071 | PC 1904 | PUSH2 | gas 950159
TestContract.sol:32 in increment
   32 |         emit CounterIncremented(counter);
soldb> reverse-next
Step 962/1071 | PC 1903 | JUMPDEST | gas 950160
TestContract.sol:30 in increment
   30 |         increment2(amount);
soldb> q
Exiting debugger.
```
