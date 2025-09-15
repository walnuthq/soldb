# SolDB – Local Solidity Debugger

> **Note**: SolDB is in public beta; expect ongoing changes and occasional inaccuracies.  

> **Note**: SolDB relies on ETHDebug metadata. Complete, accurate debug info implies better breakpoints/stepping/variable views; incomplete info can cause gaps or inconsistencies.

SolDB is an open-source, LLDB-style debugger for Solidity and the EVM.

![soldb demo 11 sept 2025](https://github.com/user-attachments/assets/7376da04-96b0-4aae-8c9b-154680ffe6b4)


---

## Quick Start

Install via pip:
```bash
pip install git+https://github.com/walnuthq/soldb.git
```

Run against a local node (Anvil):
```bash
anvil --steps-tracing
```

Compile your contracts with ETHDebug (Solidity 0.8.29+):
```bash
solc --via-ir --debug-info ethdebug --ethdebug --ethdebug-runtime --bin --abi --overwrite -o out examples/Counter.sol
```

Trace a transaction:
```bash
soldb trace <tx_hash> --ethdebug-dir <contract_address>:<contract_name>:./out --rpc http://localhost:8545
```

---

## Example: Debugging a Transaction

```bash
soldb trace 0x2832...3994 --ethdebug-dir 0x3aa5ebb10dc797cac828524e59a333d0a371443c:TestContract:./out --rpc http://localhost:8545
```

Output:
```
Contract: TestContract
Gas used: 50835
Status: SUCCESS

Call Stack:
#0 TestContract::runtime_dispatcher [entry] @ TestContract.sol:1
  #1 increment [external] gas: 29241 @ TestContract.sol:23
    #2 increment2 [internal] gas: 6322 @ TestContract.sol:39
      #3 increment3 [internal] gas: 5172 @ TestContract.sol:54
```

Interactive mode:
```bash
soldb trace <tx_hash> --ethdebug-dir <contract_address>:<contract_name>:./out --rpc http://localhost:8545 --interactive
```

Inside REPL:
```
(soldb) break TestContract.sol:42
(soldb) next
(soldb) print balance
```

---

## Example: Simulating a Contract Call

Test contract functions without sending transactions on chain.

```bash
soldb simulate <contract_address> "increment(uint256)" 10 --from <sender_address> --ethdebug-dir <contract_address>:<contract_name>:./out --rpc http://localhost:8545
```

Output containing a simulation failure:
```
Contract: TestContract
Gas used: 27157
Status: REVERTED
Error: Value must be even

Call Stack:
#0 TestContract::runtime_dispatcher [entry] @ TestContract.sol:1
  #1 increment [external] gas: 20835 @ TestContract.sol:23 
    #2 isEven [internal] gas: 6322 @ TestContract.sol:38 !!!
```

You can also pass complex types (structs, tuples):
```bash
soldb simulate <contract_address> "submitPerson((string,uint256))" '("Alice", 30)'     --from <sender_address>     --ethdebug-dir <contract_address>:<contract_name>:./out     --rpc http://localhost:8545
```

You can also debug simulations interactively using the `--interactive` flag:

```bash
soldb simulate <contract_address> "increment(uint256)" 5     --from <sender_address>     --ethdebug-dir <contract_address>:<contract_name>:./out     --rpc http://localhost:8545     --interactive
```

Inside REPL:
```
(soldb) break TestContract.sol:38
(soldb) step
(soldb) vars
```

---

## Features

- Full transaction traces with internal calls & decoded parameters
- Transaction simulation with arbitrary calldata (including structs & tuples)
- Interactive LLDB-like REPL (`step`, `break`, `print`, etc.) – works for both transactions and simulations
- Supports any RPC (local Anvil or hosted)

---

## Use Cases

- **Local Solidity debugging**  
  Step through Solidity execution, inspect variables, debug failing fuzz tests.

- **Transaction analysis**  
  Reproduce mainnet/testnet transactions locally, pinpoint reverts or unexpected flows.

- **Tooling integrations**  
  Generate full transaction traces for explorers and dev tools (already powering [Walnut](https://github.com/walnuthq/walnut)).

---

## Advanced

### Install From Source

```bash
git clone https://github.com/walnuthq/soldb.git
cd soldb
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### Run Automated Tests

**Prerequisites**  
- RPC at `http://localhost:8545` (Anvil default)  
- Anvil running with tracing enabled:  
  ```bash
  anvil --steps-tracing
  ```
- LLVM tools (`lit`, `FileCheck`)  
  ```bash
    # Install LLVM
    # macOS
    brew install llvm
    # Ubuntu
    sudo apt-get install llvm-dev
  ```

Run tests:
```bash
cd test
./run-tests.sh SOLC_PATH=/path/to/solc
```

---

## License

SolDB is licensed under the GNU General Public License v3.0 (GPL-3.0), the same license used by Solidity and other Ethereum Foundation projects.

📄 [Full license](./LICENSE.md)

## Community & Support
💬 Join our Telegram: [@walnut_soldb](https://t.me/walnut_soldb)
📬 Email: hi@walnut.dev
