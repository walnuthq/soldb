# Renders assets/soldb-tui-demo.png: the full-screen view stopped inside
# `total`'s loop body, where `sum`, `unit`, and `i` are still live so the
# Variables pane shows values rather than <unavailable>.
#
# Run it from the repository root, with a release binary already built:
#
#   cargo build --release --bin soldb
#   vhs assets/soldb-tui.tape
#
# It needs `solc` on PATH. Only the screenshot is wanted; the GIF is a
# throwaway VHS insists on writing, so it goes to a scratch path.

Output "/tmp/soldb-tui-tape.gif"

Set Shell "bash"
# Width and Height are pixels, so they set the character grid at a given
# FontSize. Height is kept just tall enough for the panes' contents: the grid
# has no more rows than there is text to put in them, so nothing floats in
# empty space. Width stays generous, since that is what the Variables pane
# needs to print the decoded `order` struct.
Set FontSize 18
Set Width 1950
Set Height 820
Set Padding 20
Set Theme "Builtin Dark"

# Everything up to the full-screen view is setup. It stays hidden, but `Show`
# has to come back on before the `Screenshot` below: `Hide` suppresses frame
# capture, and a screenshot taken while hidden writes nothing.
Hide

Type "cd examples && clear"
Enter
Sleep 1s

# Compile with solc's legacy pipeline: its fixed stack layout is what lets the
# debugger read local variables.
Type "solc --evm-version cancun Shop.sol --bin --abi --combined-json abi,bin,bin-runtime,srcmap,srcmap-runtime,storage-layout -o out_shop --overwrite"
Enter
Sleep 2s

# No node: `run` deploys on a chain that exists only for this run and calls it.
Type "../target/release/soldb run out_shop/Shop.bin 'place(string,uint128,uint256)' widget 5 3 --ethdebug-dir 0x5fbdb2315678afecb367f032d93f642f64180aa3:Shop:out_shop -i"
Enter
Sleep 3s

# A condition on a local inside the loop, so we land on the third iteration
# with every local carrying a value.
Type "break Shop.sol:72 if sum > 10"
Enter
Sleep 1s

Type "continue"
Enter
Sleep 2s

Show

# Enter the full-screen view directly. Do not put a reverse movement before
# this: opening the TUI straight after one leaves the panes on the pre-reverse
# step while the status bar shows the current one.
Type "tui"
Enter
Sleep 3s

Type "next"
Enter
Sleep 2s

Screenshot assets/soldb-tui-demo.png
