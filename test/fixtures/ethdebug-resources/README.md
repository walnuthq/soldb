# ETHDebug resources fixture

`Resources.sol` is `test/compiler/Resources.sol`, and the JSON files are what
`solc --via-ir --debug-info ethdebug --experimental --ethdebug-program-runtime
--ethdebug-resources --storage-layout --evm-version=cancun` wrote for it: the resources
with their type and pointer tables, the storage layout of `Resources`, and its runtime
program with the program-level context listing the state variables. They were produced
by the solc branch that adds the tables and the context (argotorg/solidity#16990 and
its follow-ups) and are read by the unit tests of `soldb-ethdebug`.

Regenerate all three together when that output changes; the template names carry AST
ids, so they change whenever `Resources.sol` does.
