# Function types

`ethdebug_resources.json` is solc's output for `FunctionTypes.sol`. The Rust
integration tests resolve function parameter and return lists through tuple
references, covering empty, single- and multiple-element lists for internal and
external function types. The fixture also contains tuples contributed by function,
constructor and modifier declarations without corresponding function-type variables.

Regenerate with the solc build containing callable tuple registration:

```sh
cd test/fixtures/ethdebug-function-types
/absolute/path/to/solc FunctionTypes.sol --experimental --ethdebug-resources --overwrite -o .
```

The nested-tuple tests use handwritten schema documents because the current Solidity
syntax cannot declare a tuple-valued parameter. They check that one tuple argument or
result remains distinct from multiple arguments or results, using both references and
inline tuple wrappers.
