# SolDB REPL Commands

This document lists the commands available inside the SolDB interactive
debugger REPL.

Start the REPL with one of:

```console
soldb trace <tx_hash> --interactive
soldb simulate <contract_address> <function_signature> [args...] --from <sender> --interactive
```

The prompt is:

```text
soldb>
```

## Stepping

### `next`

Aliases: `n`

Advance to the next source step.

```text
soldb> next
soldb> n
```

Current implementation note: source-level stepping currently advances one EVM
instruction, the same as `nexti`. This keeps the REPL command shape in place
while source-aware stepping is still being built.

### `nexti`

Aliases: `ni`, `stepi`, `si`

Advance to the next EVM instruction.

```text
soldb> nexti
soldb> ni
soldb> stepi
soldb> si
```

### `step`

Aliases: `s`

Step into the next operation.

```text
soldb> step
soldb> s
```

Current implementation note: `step` currently advances one EVM instruction, the
same as `nexti`.

### `continue`

Aliases: `c`

Continue execution until the next breakpoint or the end of the trace.

```text
soldb> continue
soldb> c
```

## Navigation

### `goto <step>`

Jump to a trace step index.

```text
soldb> goto 42
```

If the requested step is outside the loaded trace, SolDB prints the valid
maximum step.

## Display Mode

### `mode`

Print the current display mode.

```text
soldb> mode
```

### `mode source`

Aliases: `mode src`

Switch to source display mode.

```text
soldb> mode source
soldb> mode src
```

### `mode asm`

Aliases: `mode assembly`

Switch to assembly display mode.

```text
soldb> mode asm
soldb> mode assembly
```

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

This command requires the interactive session to be started with ETHDebug
metadata, for example `--ethdebug-dir <address>:<contract>:<dir>`.

## Breakpoints

### `break <pc>`

Aliases: `b <pc>`

Set a breakpoint at an EVM program counter.

```text
soldb> break 141
soldb> b 0x8d
```

`<pc>` accepts decimal or hex.

### `break <file>:<line>`

Aliases: `b <file>:<line>`

Set a breakpoint at the first EVM program counter mapped to a source line by
ETHDebug metadata.

```text
soldb> break Counter.sol:7
soldb> b contracts/Counter.sol:7
```

### `break line <line>`

Aliases: `b line <line>`

Set a source-line breakpoint without naming a file. This works only when the
loaded ETHDebug metadata has a single source file; otherwise SolDB asks for the
explicit `<file>:<line>` form.

```text
soldb> break line 7
soldb> b line 7
```

### `clear <pc>`

Clear a breakpoint at an EVM program counter.

```text
soldb> clear 141
soldb> clear 0x8d
```

`<pc>` accepts decimal or hex.

### `clear <file>:<line>`

Clear a source-line breakpoint.

```text
soldb> clear Counter.sol:7
```

### `clear line <line>`

Clear a source-line breakpoint in a single-source debug session.

```text
soldb> clear line 7
```

## Help

### `help`

Print the REPL command summary.

```text
soldb> help
```

Current output:

```text
Commands: next, nexti, step, continue, goto <step>
          break <pc>|<file>:<line>|line <line>
          clear <pc>|<file>:<line>|line <line>
          info resources [--json]
          mode source|asm, help, quit
```

### `help info`

Print help for metadata inspection.

```text
soldb> help info
```

Current output:

```text
info resources [--json] - print loaded ETHDebug resources
```

### `help mode`

Print help for display modes.

```text
soldb> help mode
```

Current output:

```text
mode source|asm - switch display mode
```

## Exit

### `quit`

Aliases: `exit`, `q`

Exit the interactive debugger.

```text
soldb> quit
soldb> exit
soldb> q
```

## Example Session

```text
soldb> break Counter.sol:7
Breakpoint set at Counter.sol:7, PC 141
soldb> continue
Breakpoint hit at step 181, Counter.sol:7, PC 141
soldb> mode asm
Mode: asm
soldb> nexti
Step 182/186 | PC 142 | POP | gas 13
soldb> q
Exiting debugger.
```
