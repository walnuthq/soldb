use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use soldb_core::{SoldbError, SoldbResult};
use soldb_ethdebug::{canonical_abi_input_type, encode_abi_arguments, AbiInput};
use soldb_rpc::{HttpJsonRpcClient, RpcReceipt};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerConfig {
    pub solc_path: String,
    pub debug_output_dir: PathBuf,
    pub contracts_dir: PathBuf,
    pub build_dir: PathBuf,
    pub ethdebug_flags: Vec<String>,
    pub production_flags: Vec<String>,
}

impl Default for CompilerConfig {
    fn default() -> Self {
        Self {
            solc_path: "solc".to_owned(),
            debug_output_dir: PathBuf::from("./out"),
            contracts_dir: PathBuf::from("./contracts"),
            build_dir: PathBuf::from("./build"),
            ethdebug_flags: vec![
                "--via-ir".to_owned(),
                "--debug-info".to_owned(),
                "ethdebug".to_owned(),
                "--ethdebug".to_owned(),
                "--ethdebug-runtime".to_owned(),
                "--bin".to_owned(),
                "--abi".to_owned(),
                "--overwrite".to_owned(),
            ],
            production_flags: vec![
                "--via-ir".to_owned(),
                "--optimize".to_owned(),
                "--optimize-runs".to_owned(),
                "200".to_owned(),
                "--bin".to_owned(),
                "--abi".to_owned(),
            ],
        }
    }
}

impl CompilerConfig {
    #[must_use]
    pub fn with_paths(
        solc_path: impl Into<String>,
        debug_output_dir: impl Into<PathBuf>,
        build_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            solc_path: solc_path.into(),
            debug_output_dir: debug_output_dir.into(),
            build_dir: build_dir.into(),
            ..Self::default()
        }
    }

    pub fn ensure_directories(&self) -> SoldbResult<()> {
        fs::create_dir_all(&self.debug_output_dir).map_err(|error| {
            SoldbError::Message(format!(
                "Failed to create debug output dir {}: {error}",
                self.debug_output_dir.display()
            ))
        })?;
        fs::create_dir_all(&self.build_dir).map_err(|error| {
            SoldbError::Message(format!(
                "Failed to create build dir {}: {error}",
                self.build_dir.display()
            ))
        })?;
        Ok(())
    }

    pub fn compile_with_ethdebug(
        &self,
        contract_file: impl AsRef<Path>,
        output_dir: Option<&Path>,
    ) -> SoldbResult<CompilationResult> {
        let output_dir = output_dir.unwrap_or(&self.debug_output_dir);
        self.ensure_directories()?;
        run_solc(
            &self.solc_path,
            &self.ethdebug_flags,
            contract_file.as_ref(),
            output_dir,
        )
    }

    pub fn compile_for_production(
        &self,
        contract_file: impl AsRef<Path>,
        output_dir: Option<&Path>,
    ) -> SoldbResult<CompilationResult> {
        let output_dir = output_dir.unwrap_or(&self.build_dir);
        self.ensure_directories()?;
        run_solc(
            &self.solc_path,
            &self.production_flags,
            contract_file.as_ref(),
            output_dir,
        )
    }

    pub fn verify_solc_version(&self) -> VersionInfo {
        let output = match Command::new(&self.solc_path).arg("--version").output() {
            Ok(output) => output,
            Err(error) => {
                return VersionInfo {
                    supported: false,
                    version: None,
                    full_output: None,
                    error: Some(error.to_string()),
                };
            }
        };

        if !output.status.success() {
            return VersionInfo {
                supported: false,
                version: None,
                full_output: Some(String::from_utf8_lossy(&output.stderr).into_owned()),
                error: Some("Could not get solc version".to_owned()),
            };
        }

        let full_output = String::from_utf8_lossy(&output.stdout).into_owned();
        let Some(version) = extract_solc_version(&full_output) else {
            return VersionInfo {
                supported: false,
                version: None,
                full_output: Some(full_output),
                error: Some("Could not parse version".to_owned()),
            };
        };

        let supported = version_supports_ethdebug(&version);
        VersionInfo {
            supported,
            version: Some(version.clone()),
            full_output: Some(full_output),
            error: (!supported).then(|| {
                format!("Solidity {version} does not support ETHDebug (requires 0.8.29+)")
            }),
        }
    }

    pub fn save_to_soldb_config(&self, config_file: impl AsRef<Path>) -> SoldbResult<()> {
        let content = format!(
            "\
debug:
  ethdebug:
    enabled: true
    path: {}
    solc_path: {}
    fallback_to_heuristics: true
    compile_options:
      via_ir: true
      optimizer: true
      optimizer_runs: 200
build_dir: {}
",
            self.debug_output_dir.display(),
            self.solc_path,
            self.build_dir.display()
        );
        fs::write(config_file.as_ref(), content).map_err(|error| {
            SoldbError::Message(format!(
                "Failed to write config {}: {error}",
                config_file.as_ref().display()
            ))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilationResult {
    pub success: bool,
    pub output_dir: PathBuf,
    pub files: CompilerOutputFiles,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerOutputFiles {
    pub ethdebug: Option<PathBuf>,
    pub contracts: BTreeMap<String, ContractArtifactFiles>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractArtifactFiles {
    pub bytecode: Option<PathBuf>,
    pub abi: Option<PathBuf>,
    pub ethdebug: Option<PathBuf>,
    pub ethdebug_runtime: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionInfo {
    pub supported: bool,
    pub version: Option<String>,
    pub full_output: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DualCompileResult {
    pub production: Result<CompilationResult, String>,
    pub debug: Result<CompilationResult, String>,
}

pub fn dual_compile(contract_file: impl AsRef<Path>, config: &CompilerConfig) -> DualCompileResult {
    let contract_file = contract_file.as_ref();
    DualCompileResult {
        production: config
            .compile_for_production(contract_file, None)
            .map_err(|error| error.to_string()),
        debug: config
            .compile_with_ethdebug(contract_file, None)
            .map_err(|error| error.to_string()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoDeployConfig {
    pub contract_file: PathBuf,
    pub rpc_url: String,
    pub compiler: CompilerConfig,
    pub dual_compile: bool,
    pub verify_version: bool,
    pub save_config: bool,
    pub constructor_args: Vec<String>,
    pub deployer: Option<String>,
}

impl AutoDeployConfig {
    #[must_use]
    pub fn new(contract_file: impl Into<PathBuf>, rpc_url: impl Into<String>) -> Self {
        Self {
            contract_file: contract_file.into(),
            rpc_url: rpc_url.into(),
            compiler: CompilerConfig::default(),
            dual_compile: false,
            verify_version: false,
            save_config: false,
            constructor_args: Vec::new(),
            deployer: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoDeployResult {
    pub contract_name: String,
    pub contract_address: String,
    pub transaction_hash: String,
    pub debug_dir: PathBuf,
    pub abi_path: PathBuf,
    pub bin_path: PathBuf,
    pub compile: CompilationResult,
}

pub fn auto_deploy(config: &AutoDeployConfig) -> SoldbResult<AutoDeployResult> {
    if !config.contract_file.exists() {
        return Err(SoldbError::Message(format!(
            "Contract file not found: {}",
            config.contract_file.display()
        )));
    }
    if config.verify_version {
        let version = config.compiler.verify_solc_version();
        if !version.supported {
            return Err(SoldbError::Message(
                version
                    .error
                    .unwrap_or_else(|| "Unsupported solc version".to_owned()),
            ));
        }
    }
    if config.save_config {
        config.compiler.save_to_soldb_config("soldb.config.yaml")?;
    }

    let contract_name = config
        .contract_file
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or_else(|| SoldbError::Message("Invalid contract file name".to_owned()))?
        .to_owned();

    let (compile, abi_path, bin_path, debug_dir) = compile_for_deploy(config, &contract_name)?;
    let abi = read_abi(&abi_path)?;
    let constructor_data = encode_constructor_args(&abi, &config.constructor_args)?;
    let bytecode = read_bytecode(&bin_path)?;
    let deploy_data = format!("{bytecode}{constructor_data}");

    let client = HttpJsonRpcClient::new(&config.rpc_url)?;
    let deployer = match &config.deployer {
        Some(deployer) => deployer.clone(),
        None => {
            let accounts: Vec<String> = client.request("eth_accounts", json!([]))?;
            accounts.first().cloned().ok_or_else(|| {
                SoldbError::Message("RPC returned no deployer accounts".to_owned())
            })?
        }
    };

    let transaction_hash: String = client.request(
        "eth_sendTransaction",
        json!([{
            "from": deployer,
            "data": deploy_data,
        }]),
    )?;
    let receipt = wait_for_receipt(&client, &transaction_hash)?;
    let contract_address = receipt.contract_address.ok_or_else(|| {
        SoldbError::Message(format!(
            "Deployment transaction {transaction_hash} did not produce a contract address"
        ))
    })?;

    write_deployment_json(
        &debug_dir,
        &contract_name,
        &contract_address,
        &transaction_hash,
    )?;

    Ok(AutoDeployResult {
        contract_name,
        contract_address,
        transaction_hash,
        debug_dir,
        abi_path,
        bin_path,
        compile,
    })
}

fn run_solc(
    solc_path: &str,
    flags: &[String],
    contract_file: &Path,
    output_dir: &Path,
) -> SoldbResult<CompilationResult> {
    fs::create_dir_all(output_dir).map_err(|error| {
        SoldbError::Message(format!(
            "Failed to create output dir {}: {error}",
            output_dir.display()
        ))
    })?;

    let mut command = Command::new(solc_path);
    command.args(flags);
    command.arg("-o").arg(output_dir).arg(contract_file);
    let output = command.output().map_err(|error| {
        SoldbError::Message(format!(
            "Failed to start Solidity compiler {solc_path}: {error}"
        ))
    })?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(SoldbError::Message(format!(
            "Compilation failed:\n{}",
            stderr.trim()
        )));
    }

    Ok(CompilationResult {
        success: true,
        output_dir: output_dir.to_path_buf(),
        files: discover_output_files(output_dir)?,
        stdout,
        stderr,
    })
}

fn discover_output_files(output_dir: &Path) -> SoldbResult<CompilerOutputFiles> {
    let mut files = CompilerOutputFiles {
        ethdebug: output_dir
            .join("ethdebug.json")
            .exists()
            .then(|| output_dir.join("ethdebug.json")),
        contracts: BTreeMap::new(),
    };

    let entries = fs::read_dir(output_dir).map_err(|error| {
        SoldbError::Message(format!(
            "Failed to read compiler output dir {}: {error}",
            output_dir.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            SoldbError::Message(format!("Failed to read compiler output entry: {error}"))
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("bin") {
            continue;
        }
        let Some(contract_name) = path.file_stem().and_then(|name| name.to_str()) else {
            continue;
        };
        let contract_name = contract_name.to_owned();
        files.contracts.insert(
            contract_name.clone(),
            ContractArtifactFiles {
                bytecode: Some(path),
                abi: existing_path(output_dir.join(format!("{contract_name}.abi"))),
                ethdebug: existing_path(output_dir.join(format!("{contract_name}_ethdebug.json"))),
                ethdebug_runtime: existing_path(
                    output_dir.join(format!("{contract_name}_ethdebug-runtime.json")),
                ),
            },
        );
    }

    Ok(files)
}

fn existing_path(path: PathBuf) -> Option<PathBuf> {
    path.exists().then_some(path)
}

fn extract_solc_version(output: &str) -> Option<String> {
    let marker = "Version:";
    let after_marker = output.split(marker).nth(1)?.trim();
    let version = after_marker
        .split_whitespace()
        .next()?
        .split('+')
        .next()?
        .trim();
    (!version.is_empty()).then(|| version.to_owned())
}

fn version_supports_ethdebug(version: &str) -> bool {
    let parts = version
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>();
    let Ok(parts) = parts else {
        return false;
    };
    let [major, minor, patch] = parts.as_slice() else {
        return false;
    };
    *major > 0 || (*major == 0 && (*minor > 8 || (*minor == 8 && *patch >= 29)))
}

fn compile_for_deploy(
    config: &AutoDeployConfig,
    contract_name: &str,
) -> SoldbResult<(CompilationResult, PathBuf, PathBuf, PathBuf)> {
    if config.dual_compile {
        let result = dual_compile(&config.contract_file, &config.compiler);
        let production = result.production.map_err(|error| {
            SoldbError::Message(format!("Production compilation failed: {error}"))
        })?;
        let debug = result.debug.map_err(|error| {
            SoldbError::Message(format!("ETHDebug compilation failed: {error}"))
        })?;
        let abi_path = production
            .files
            .contracts
            .get(contract_name)
            .and_then(|files| files.abi.clone())
            .ok_or_else(|| {
                SoldbError::Message(format!("Missing production ABI for {contract_name}"))
            })?;
        let bin_path = production
            .files
            .contracts
            .get(contract_name)
            .and_then(|files| files.bytecode.clone())
            .ok_or_else(|| {
                SoldbError::Message(format!("Missing production bytecode for {contract_name}"))
            })?;
        return Ok((debug.clone(), abi_path, bin_path, debug.output_dir));
    }

    let compile = config
        .compiler
        .compile_with_ethdebug(&config.contract_file, None)?;
    let artifacts = compile
        .files
        .contracts
        .get(contract_name)
        .ok_or_else(|| SoldbError::Message(format!("Missing artifacts for {contract_name}")))?;
    let abi_path = artifacts
        .abi
        .clone()
        .ok_or_else(|| SoldbError::Message(format!("Missing ABI for {contract_name}")))?;
    let bin_path = artifacts
        .bytecode
        .clone()
        .ok_or_else(|| SoldbError::Message(format!("Missing bytecode for {contract_name}")))?;
    let debug_dir = compile.output_dir.clone();
    Ok((compile, abi_path, bin_path, debug_dir))
}

fn read_abi(path: &Path) -> SoldbResult<Vec<Value>> {
    let content = fs::read_to_string(path).map_err(|error| {
        SoldbError::Message(format!("Failed to read ABI {}: {error}", path.display()))
    })?;
    serde_json::from_str::<Vec<Value>>(&content).map_err(|error| {
        SoldbError::Message(format!("Invalid ABI JSON {}: {error}", path.display()))
    })
}

fn read_bytecode(path: &Path) -> SoldbResult<String> {
    let bytecode = fs::read_to_string(path).map_err(|error| {
        SoldbError::Message(format!(
            "Failed to read bytecode {}: {error}",
            path.display()
        ))
    })?;
    let bytecode = bytecode.trim().trim_start_matches("0x");
    if bytecode.is_empty() || !bytecode.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SoldbError::Message(format!(
            "Invalid bytecode in {}",
            path.display()
        )));
    }
    Ok(format!("0x{}", bytecode.to_ascii_lowercase()))
}

fn encode_constructor_args(abi: &[Value], args: &[String]) -> SoldbResult<String> {
    let constructor = abi
        .iter()
        .find(|item| item.get("type").and_then(Value::as_str) == Some("constructor"));
    let inputs = constructor
        .and_then(|item| item.get("inputs"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    if inputs.is_empty() && args.is_empty() {
        return Ok(String::new());
    }

    let inputs = inputs
        .into_iter()
        .map(serde_json::from_value::<AbiInput>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| SoldbError::Message(format!("Invalid constructor ABI: {error}")))?;
    let arg_types = inputs
        .iter()
        .map(canonical_abi_input_type)
        .collect::<Vec<_>>();
    encode_abi_arguments(&arg_types, args)
}

fn wait_for_receipt(client: &HttpJsonRpcClient, tx_hash: &str) -> SoldbResult<RpcReceipt> {
    for _ in 0..100 {
        let receipt: Option<RpcReceipt> =
            client.request("eth_getTransactionReceipt", json!([tx_hash]))?;
        if let Some(receipt) = receipt {
            return Ok(receipt);
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(SoldbError::Message(format!(
        "Timed out waiting for deployment receipt {tx_hash}"
    )))
}

fn write_deployment_json(
    debug_dir: &Path,
    contract_name: &str,
    contract_address: &str,
    transaction_hash: &str,
) -> SoldbResult<()> {
    let path = debug_dir.join("deployment.json");
    let content = serde_json::to_string_pretty(&json!({
        "address": contract_address,
        "transaction": transaction_hash,
        "contract": contract_name,
        "ethdebug": {"enabled": true},
    }))
    .map_err(|error| {
        SoldbError::Message(format!("Failed to serialize deployment.json: {error}"))
    })?;
    fs::write(&path, content).map_err(|error| {
        SoldbError::Message(format!("Failed to write {}: {error}", path.display()))
    })
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{auto_deploy, dual_compile, AutoDeployConfig, CompilerConfig};
    use serde_json::json;

    #[test]
    #[cfg(unix)]
    fn compiles_ethdebug_and_discovers_outputs() {
        let temp = temp_dir("compile");
        let solc = fake_solc(&temp, "0.8.31", false);
        let contract = temp.join("Counter.sol");
        std::fs::write(&contract, "contract Counter {}").expect("write contract");
        let out = temp.join("out");
        let cfg = CompilerConfig::with_paths(solc.to_string_lossy(), &out, temp.join("build"));

        let result = cfg
            .compile_with_ethdebug(&contract, None)
            .expect("compile succeeds");

        assert!(result.success);
        assert!(result.files.ethdebug.is_some());
        let files = result
            .files
            .contracts
            .get("Counter")
            .expect("counter files");
        assert!(files.bytecode.as_ref().expect("bin").exists());
        assert!(files.abi.as_ref().expect("abi").exists());
        assert!(files.ethdebug.as_ref().expect("ethdebug").exists());
    }

    #[test]
    #[cfg(unix)]
    fn verifies_solc_ethdebug_version_floor() {
        let temp = temp_dir("version");
        let new_solc = fake_solc(&temp, "0.8.31", false);
        let old_solc = fake_solc(&temp, "0.8.28", false);

        let new_info = CompilerConfig {
            solc_path: new_solc.to_string_lossy().into_owned(),
            ..CompilerConfig::default()
        }
        .verify_solc_version();
        let old_info = CompilerConfig {
            solc_path: old_solc.to_string_lossy().into_owned(),
            ..CompilerConfig::default()
        }
        .verify_solc_version();

        assert!(new_info.supported);
        assert!(!old_info.supported);
        assert_eq!(old_info.version.as_deref(), Some("0.8.28"));
    }

    #[test]
    #[cfg(unix)]
    fn dual_compile_reports_both_outputs() {
        let temp = temp_dir("dual");
        let solc = fake_solc(&temp, "0.8.31", false);
        let contract = temp.join("Counter.sol");
        std::fs::write(&contract, "contract Counter {}").expect("write contract");
        let cfg = CompilerConfig::with_paths(
            solc.to_string_lossy(),
            temp.join("debug"),
            temp.join("production"),
        );

        let result = dual_compile(&contract, &cfg);

        assert!(result.production.is_ok());
        assert!(result.debug.is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn auto_deploy_compiles_sends_transaction_and_writes_metadata() {
        let temp = temp_dir("deploy");
        let solc = fake_solc(&temp, "0.8.31", true);
        let contract = temp.join("Counter.sol");
        std::fs::write(&contract, "contract Counter { constructor(uint256 n) {} }")
            .expect("write contract");
        let rpc_url = start_deploy_rpc_server();
        let mut cfg = AutoDeployConfig::new(&contract, rpc_url);
        cfg.compiler = CompilerConfig::with_paths(
            solc.to_string_lossy(),
            temp.join("debug"),
            temp.join("production"),
        );
        cfg.constructor_args = vec!["7".to_owned()];

        let result = auto_deploy(&cfg).expect("auto deploy");

        assert_eq!(
            result.contract_address,
            "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        );
        assert!(result.debug_dir.join("deployment.json").exists());
    }

    #[cfg(unix)]
    fn fake_solc(root: &std::path::Path, version: &str, constructor: bool) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = root.join(format!("solc-{version}-{constructor}"));
        let constructor_abi = if constructor {
            r#", {"type":"constructor","inputs":[{"name":"n","type":"uint256"}]}"#
        } else {
            ""
        };
        let script = format!(
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "solc, the solidity compiler"
  echo "Version: {version}+commit.test"
  exit 0
fi
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-o" ]; then
    out="$arg"
  fi
  prev="$arg"
done
mkdir -p "$out"
cat > "$out/ethdebug.json" <<'EOF'
{{"version":1}}
EOF
cat > "$out/Counter.abi" <<'EOF'
[{{"type":"function","name":"get","inputs":[]}}{constructor_abi}]
EOF
cat > "$out/Counter.bin" <<'EOF'
6001600055
EOF
cat > "$out/Counter_ethdebug.json" <<'EOF'
{{"contract":"Counter"}}
EOF
cat > "$out/Counter_ethdebug-runtime.json" <<'EOF'
{{"contract":"Counter"}}
EOF
"#
        );
        std::fs::write(&path, script).expect("write solc");
        let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod");
        path
    }

    fn start_deploy_rpc_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind rpc server");
        let address = listener.local_addr().expect("local addr");
        std::thread::spawn(move || {
            for _ in 0..3 {
                let (stream, _) = listener.accept().expect("accept rpc");
                respond_to_rpc(stream);
            }
        });
        format!("http://{address}")
    }

    fn respond_to_rpc(mut stream: TcpStream) {
        let request = read_http_request(&mut stream);
        let response = if request.contains("\"eth_accounts\"") {
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": ["0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"]
            })
        } else if request.contains("\"eth_sendTransaction\"") {
            assert!(request.contains("6001600055"));
            assert!(request
                .contains("0000000000000000000000000000000000000000000000000000000000000007"));
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": "0x85368076afa1f63460e6f98fe3f2a85d121c4b9c0086ed37fc20022ebea4964c"
            })
        } else if request.contains("\"eth_getTransactionReceipt\"") {
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "gasUsed": "0x5208",
                    "status": "0x1",
                    "contractAddress": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
                    "logs": []
                }
            })
        } else {
            json!({"jsonrpc": "2.0", "id": 1, "error": {"message": "unknown method"}})
        };

        let body = response.to_string();
        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(http_response.as_bytes()).expect("write");
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut data = Vec::new();
        let mut buffer = [0_u8; 512];
        loop {
            let read = stream.read(&mut buffer).expect("read");
            if read == 0 {
                break;
            }
            data.extend_from_slice(&buffer[..read]);
            if let Some(header_end) = find_header_end(&data) {
                let headers = String::from_utf8_lossy(&data[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                if data.len().saturating_sub(header_end + 4) >= content_length {
                    break;
                }
            }
        }
        String::from_utf8(data).expect("utf8")
    }

    fn find_header_end(data: &[u8]) -> Option<usize> {
        data.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("soldb-compiler-{label}-{unique}"));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }
}
