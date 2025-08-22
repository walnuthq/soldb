import subprocess
import os
import re
import json
import tempfile
import shutil
import hashlib
import time
import ast
from pathlib import Path
from web3 import Web3
from typing import Any, List, Optional, Dict

from .evm_repl import EVMDebugger
from .colors import info, warning, error
from .compiler_config import CompilationError
from .compile_ethdebug import compile_ethdebug_run

class AutoDeployDebugger:
    def __init__(
        self,
        contract_file: str,
        rpc_url: str = "http://localhost:8545",
        solc_path: str = "solc",
        dual_compile: bool = False,
        keep_build: bool = False,
        output_dir: str = "./build/debug/ethdebug",
        production_dir: str = "./build/contracts",
        verify_version: bool = False,
        save_config: bool = False,
        json_output: bool = False,
        use_cache: bool = True,
        cache_dir: str = ".soldb_cache",
        fork_url: str = None,
        fork_block: int = None,
        auto_snapshot: bool = True,
        constructor_args: list = [],
        keep_fork: bool = False,
        reuse_fork: bool = False,
        fork_port: int = 8545,
    ):
        self.contract_path = Path(contract_file)
        if not self.contract_path.exists():
            raise FileNotFoundError(f"Contract file not found: {contract_file}")

        self.contract_name = self.contract_path.stem
        self.rpc_url = rpc_url
        self.solc_path = solc_path
        self.dual_compile = dual_compile
        self.keep_build = keep_build
        self.verify_version = verify_version
        self.save_config = save_config
        self.json_output = json_output
        self.constructor_args = constructor_args

        # Use provided directories or create temp ones
        if self.keep_build:
            # Create contract-specific subdirectories to avoid conflicts
            base_debug_dir = Path(output_dir)
            base_production_dir = Path(production_dir)
            self.debug_output_dir = base_debug_dir / self.contract_name
            self.production_dir = base_production_dir / self.contract_name
            self.debug_output_dir.mkdir(parents=True, exist_ok=True)
            self.production_dir.mkdir(parents=True, exist_ok=True)
        else:
            # Temp directory for ETHDebug artifacts when not keeping build
            self.temp_dir = Path(tempfile.mkdtemp(prefix=f"soldb-{self.contract_name}-"))
            self.debug_output_dir = self.temp_dir
            self.production_dir = self.temp_dir / "prod"
            self.production_dir.mkdir(parents=True, exist_ok=True)

        self._compile_result = None
        self.contract_address = None
        self.abi_path = None
        self.bin_path = None
        self.debug_dir = None
        self.debugger: EVMDebugger | None = None

        self.use_cache = use_cache
        self.cache_root = Path(cache_dir)
        self.cache_root.mkdir(parents=True, exist_ok=True)
        self.fork_url = fork_url
        self.fork_block = fork_block
        self._fork_proc: subprocess.Popen | None = None
        self.auto_snapshot = auto_snapshot
        self.keep_fork = keep_fork
        self.reuse_fork = reuse_fork
        self.fork_port = fork_port
        # connect to existing fork or launch a new one (if configured)
        self.connect_or_launch_fork()
        # workflow
        if not self._try_cache_hit():
            self.compile_contract()
            self.deploy_contract()
            self._store_cache()

    def connect_or_launch_fork(self):
        """
        If --reuse-fork is set, try to connect to an existing local dev node (anvil/hardhat)
        on --fork-port even when --fork-url is not provided. Otherwise, launch a new fork
        only when --fork-url is specified.
        """
        target_rpc = f"http://127.0.0.1:{self.fork_port}"
        if self.reuse_fork and self._is_local_fork_running(target_rpc):
            print(info(f"[FORK] reusing existing fork at {target_rpc}"))
            self.rpc_url = target_rpc
            return
        if self.fork_url:
            self._launch_fork()
            return

    def _launch_fork(self):
        # Reuse existing local fork if asked and reachable
        target_rpc = f"http://127.0.0.1:{self.fork_port}"
        if self.reuse_fork and self._is_local_fork_running(target_rpc): 
            print(info(f"[FORK] reusing existing fork at {target_rpc}"))
            self.rpc_url = target_rpc
            return
        print(info(f"[FORK] starting anvil fork from {self.fork_url}" + (f" @ block {self.fork_block}" if self.fork_block else "")))
        args = ["anvil", "--fork-url", self.fork_url, "--port", str(self.fork_port)]
        if self.fork_block is not None:
            args += ["--fork-block-number", str(self.fork_block)]
        self._fork_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.rpc_url = target_rpc
        # wait until responsive
        for _ in range(50):
            try:
                w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 0.2}))
                if w3.is_connected():
                    _ = w3.eth.block_number
                    break
            except Exception:
                pass
            time.sleep(0.1)
            
    def _is_local_fork_running(self, url: str) -> bool:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 0.2}))
            if not w3.is_connected():
                return False
            # Try client version to ensure it’s a dev node (anvil/hardhat)
            try:
                ver = w3.client_version
            except Exception:
                ver = w3.provider.make_request("web3_clientVersion", []).get("result", "")
            return isinstance(ver, str) and ("anvil" in ver.lower() or "hardhat" in ver.lower())
        except Exception:
            return False

    def cleanup(self):
        try:
            if self._fork_proc and self._fork_proc.poll() is None:
                if self.keep_fork:
                    print(info(f"[FORK] keeping fork alive at {self.rpc_url}"))
                else:
                    self._fork_proc.terminate()
        except Exception:
            pass
        
    def _artifact_fingerprint(self) -> str:
        data = {
            "file": self.contract_path.read_bytes(),
            "solc": self.solc_path.encode(),
            "args": json.dumps(self.constructor_args).encode(),
            "dual": b"1" if self.dual_compile else b"0"
        }
        h = hashlib.sha256()
        for v in data.values():
            h.update(v)
        return h.hexdigest()

    def _cache_entry_path(self) -> Path:
        return self.cache_root / self._artifact_fingerprint()

    def _try_cache_hit(self) -> bool:
        if not self.use_cache:
            return False
        entry = self._cache_entry_path()
        meta = entry / "meta.json"
        if not meta.exists():
            return False
        try:
            with open(meta) as f:
                info_json = json.load(f)
            w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            chain_id = w3.eth.chain_id
            if info_json.get("chain_id") != chain_id:
                return False
            addr = info_json["address"]
            
            on_chain_code = w3.eth.get_code(addr).hex()
            if on_chain_code != info_json.get("runtime_code", ""):
                return False
            # hydrate
            self.contract_address = addr
            self.debug_dir = entry / "debug"
            self.abi_path = entry / "artifacts" / f"{self.contract_name}.abi"
            self.bin_path = entry / "artifacts" / f"{self.contract_name}.bin"
            if not (self.abi_path.exists() and self.bin_path.exists()):
                return False
            print(info(f"[CACHE] hit -> {addr}"))
            return True
        except Exception as e:
            print(warning(f"[CACHE] miss ({e})"))
            return False

    def _store_cache(self):
        if not self.use_cache or not self.contract_address:
            return
        entry = self._cache_entry_path()
        if entry.exists():
            return
        (entry / "artifacts").mkdir(parents=True, exist_ok=True)
        (entry / "debug").mkdir(exist_ok=True)
        # copy artifacts
        shutil.copy2(self.abi_path, entry / "artifacts" / self.abi_path.name)
        shutil.copy2(self.bin_path, entry / "artifacts" / self.bin_path.name)
        # copy debug json files
        for f in Path(self.debug_dir).glob("*ethdebug*.json"):
            shutil.copy2(f, entry / "debug" / f.name)
        w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        runtime_code = w3.eth.get_code(self.contract_address).hex()
        meta = {
            "address": self.contract_address,
            "chain_id": w3.eth.chain_id,
            "runtime_code": runtime_code,
            "constructor_args": self.constructor_args,
            "dual": self.dual_compile
        }
        with open(entry / "meta.json", "w") as f:
            json.dump(meta, f, indent=2)
        print(info(f"[CACHE] stored ({entry.name})"))

    def compile_contract(self):
        print(info("\n--- Verifying solc & Compiling ---"))
    
        try:
            self._compile_result = compile_ethdebug_run(
                contract_file=str(self.contract_path),
                solc_path=self.solc_path,
                debug_output_dir=str(self.debug_output_dir),
                production_dir=str(self.production_dir),
                dual=self.dual_compile,
                verify_version=self.verify_version
            )

            if self.verify_version:
                if not self._compile_result.get("supported"):
                    raise CompilationError(self._compile_result.get("error", "Unsupported solc version"))
                print(info(f"solc {self._compile_result['version']} OK (ETHDebug supported)"))
        except Exception as e:
            raise CompilationError(f"Compilation error: {e}") from e

        if self.dual_compile:
            prod = self._compile_result.get("production", {})
            dbg = self._compile_result.get("debug", {})
            if not (prod.get("success") and dbg.get("success")):
                raise CompilationError("Dual compile failed")
            prod_dir = Path(prod["output_dir"])
            dbg_dir = Path(dbg["output_dir"])
            self.abi_path = prod_dir / f"{self.contract_name}.abi"
            self.bin_path = prod_dir / f"{self.contract_name}.bin"
            self.debug_dir = dbg_dir
            print(info(f"✓ Dual compile successful"))
        else:
            if not self._compile_result.get("success"):
                raise CompilationError(self._compile_result.get("error", "Compilation failed"))
            out_dir = Path(self._compile_result["output_dir"])
            self.abi_path = out_dir / f"{self.contract_name}.abi"
            self.bin_path = out_dir / f"{self.contract_name}.bin"
            self.debug_dir = out_dir
            print(info(f"✓ Compiled {self.contract_name} to {self.debug_dir}"))

        if not self.abi_path.exists() or not self.bin_path.exists():
            raise FileNotFoundError("Missing ABI or BIN after compile")

        print(info(f"✓ ABI: {self.abi_path}"))
        print(info(f"✓ BIN: {self.bin_path}"))
        print(info(f"✓ Debug artifacts: {self.debug_dir}"))

    def deploy_contract(self):
        print(info("\n--- Deploying Contract ---"))
        w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        if not w3.is_connected():
            raise ConnectionError(f"Cannot connect to {self.rpc_url}")

        # Load ABI + BIN
        with open(self.abi_path) as f:
            abi = json.load(f)
        bytecode = Path(self.bin_path).read_text().strip()

        # Parse constructor args to correct types based on ABI
        ctor_inputs = self._get_constructor_inputs(abi)
        ctor_args = self._parse_constructor_args(self.constructor_args, ctor_inputs)

        deployer = w3.eth.accounts[0]
        Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash = Contract.constructor(*ctor_args).transact({'from': deployer})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        self.contract_address = receipt.contractAddress
        print(info(f"✓ Deployed {self.contract_name} at {self.contract_address}"))

    # ---------- Constructor arg parsing ----------
    def _get_constructor_inputs(self, abi: List[dict]) -> List[dict]:
        for item in abi:
            if item.get("type") == "constructor":
                return item.get("inputs", [])
        return []

    def _parse_constructor_args(self, raw_args: List[str], inputs: List[dict]) -> List[Any]:
        if len(raw_args) != len(inputs):
            raise ValueError(f"Constructor expects {len(inputs)} args, got {len(raw_args)}")
        return [self._parse_arg(val, inp) for val, inp in zip(raw_args, inputs)]

    def _parse_arg(self, val: str, inp: dict) -> Any:
        typ = inp["type"]
     
        # Arrays
        if typ.endswith("]"):
            # Expect Python/JSON list input: "[1,2]" or "['a','b']"
            parsed = ast.literal_eval(val) if isinstance(val, str) else val
            if not isinstance(parsed, (list, tuple)):
                raise ValueError(f"Argument for {typ} must be a list")
            base = typ[:typ.index("[")]
            comps = inp.get("components")
            return [self._parse_typed(elem, base, comps) for elem in parsed]
        # Tuples
        if typ.startswith("tuple"):
            parsed = ast.literal_eval(val) if isinstance(val, str) else val
            if not isinstance(parsed, (list, tuple)):
                raise ValueError("Tuple arg must be a list/tuple")
            comps = inp.get("components", [])
            if len(parsed) != len(comps):
                raise ValueError(f"Tuple expects {len(comps)} items, got {len(parsed)}")
            return [self._parse_arg(elem, comp) for elem, comp in zip(parsed, comps)]
        # Scalars
        return self._parse_typed(val, typ, inp.get("components"))

    def _parse_typed(self, val: Any, typ: str, components: Optional[List[dict]] = None) -> Any:
        if isinstance(val, str) and typ not in ("string", "bytes"):
            try:
                val = ast.literal_eval(val)
            except Exception:
                pass
        if typ.startswith("uint") or typ.startswith("int"):
            return int(val)
        if typ == "address":
            return Web3.to_checksum_address(val)
        if typ == "bool":
            if isinstance(val, bool):
                return val
            s = str(val).lower()
            return s in ("1", "true", "yes", "y")
        if typ.startswith("bytes") and typ != "bytes":
            # fixed bytesN
            if isinstance(val, (bytes, bytearray)):
                return bytes(val)
            s = str(val)
            if s.startswith("0x"):
                return bytes.fromhex(s[2:])
            return bytes.fromhex(s)
        if typ == "bytes":
            if isinstance(val, (bytes, bytearray)):
                return bytes(val)
            s = str(val)
            if s.startswith("0x"):
                return bytes.fromhex(s[2:])
            return s.encode()
        if typ == "string":
            return str(val)
        if typ.startswith("tuple") and components:
            # handled in _parse_arg for full validation
            raise AssertionError("tuple should be handled earlier")
        # Fallback
        return val
