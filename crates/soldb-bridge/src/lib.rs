use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const PROTOCOL_VERSION: &str = "1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Evm,
    Stylus,
}

impl Environment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Evm => "evm",
            Self::Stylus => "stylus",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u64>,
}

impl SourceLocation {
    pub fn new(file: impl Into<String>, line: u64) -> Self {
        Self {
            file: file.into(),
            line,
            column: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallArgument {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub value: String,
}

impl CallArgument {
    pub fn new(name: impl Into<String>, ty: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ty: ty.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossEnvCall {
    pub call_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_call_id: Option<u64>,
    #[serde(default = "default_environment")]
    pub environment: String,
    pub contract_address: String,
    pub function_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_location: Option<SourceLocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<CallArgument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_used: Option<u64>,
    #[serde(default = "default_success")]
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default = "default_call_type")]
    pub call_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
    #[serde(default)]
    pub children: Vec<CrossEnvCall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_env_ref: Option<String>,
}

impl CrossEnvCall {
    pub fn new(
        call_id: u64,
        environment: impl Into<String>,
        contract_address: impl Into<String>,
        function_name: impl Into<String>,
    ) -> Self {
        Self {
            call_id,
            parent_call_id: None,
            environment: environment.into(),
            contract_address: contract_address.into(),
            function_name: function_name.into(),
            function_selector: None,
            function_signature: None,
            source_location: None,
            args: Vec::new(),
            return_data: None,
            return_value: None,
            gas_used: None,
            success: true,
            error: None,
            call_type: default_call_type(),
            value: None,
            children: Vec::new(),
            cross_env_ref: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossEnvTrace {
    pub trace_id: String,
    #[serde(default = "default_protocol_version")]
    pub protocol_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_call: Option<CrossEnvCall>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<CrossEnvCall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_used: Option<u64>,
    #[serde(default = "default_success")]
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CrossEnvTrace {
    pub fn new(trace_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            protocol_version: default_protocol_version(),
            transaction_hash: None,
            root_call: None,
            calls: Vec::new(),
            from_address: None,
            to_address: None,
            value: None,
            gas_used: None,
            success: true,
            error: None,
        }
    }

    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(input: &str) -> serde_json::Result<Self> {
        serde_json::from_str(input)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractInfo {
    pub address: String,
    #[serde(default = "default_environment")]
    pub environment: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lib_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_files: Vec<String>,
}

impl ContractInfo {
    pub fn new(
        address: impl Into<String>,
        environment: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            address: address.into(),
            environment: environment.into(),
            name: name.into(),
            debug_dir: None,
            lib_path: None,
            project_path: None,
            compiler_version: None,
            source_files: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceRequest {
    pub request_id: String,
    pub transaction_hash: Option<String>,
    pub block_number: Option<u64>,
    pub rpc_endpoint: Option<String>,
    #[serde(default)]
    pub target_address: String,
    pub caller_address: Option<String>,
    #[serde(default)]
    pub calldata: String,
    #[serde(default)]
    pub value: u64,
    #[serde(default)]
    pub depth: u64,
    pub parent_call_id: Option<u64>,
    pub parent_trace_id: Option<String>,
    #[serde(default = "default_environment")]
    pub source_environment: String,
}

impl TraceRequest {
    pub fn new(request_id: impl Into<String>, target_address: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            transaction_hash: None,
            block_number: None,
            rpc_endpoint: None,
            target_address: target_address.into(),
            caller_address: None,
            calldata: String::new(),
            value: 0,
            depth: 0,
            parent_call_id: None,
            parent_trace_id: None,
            source_environment: default_environment(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceResponse {
    pub request_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<CrossEnvTrace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

impl TraceResponse {
    pub fn success(request_id: impl Into<String>, trace: CrossEnvTrace) -> Self {
        Self {
            request_id: request_id.into(),
            status: "success".to_owned(),
            trace: Some(trace),
            error_message: None,
            error_code: None,
        }
    }

    pub fn error(
        request_id: impl Into<String>,
        message: impl Into<String>,
        code: impl Into<String>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            status: "error".to_owned(),
            trace: None,
            error_message: Some(message.into()),
            error_code: Some(code.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    Handshake,
    RegisterContract,
    UnregisterContract,
    TraceRequest,
    TraceResponse,
    SubmitTrace,
    GetContracts,
    HealthCheck,
}

impl MessageType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Handshake => "handshake",
            Self::RegisterContract => "register_contract",
            Self::UnregisterContract => "unregister_contract",
            Self::TraceRequest => "trace_request",
            Self::TraceResponse => "trace_response",
            Self::SubmitTrace => "submit_trace",
            Self::GetContracts => "get_contracts",
            Self::HealthCheck => "health_check",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BridgeMessage {
    pub message_type: String,
    pub payload: Value,
    #[serde(default = "default_protocol_version")]
    pub protocol_version: String,
}

impl BridgeMessage {
    pub fn new(message_type: MessageType, payload: Value) -> Self {
        Self {
            message_type: message_type.as_str().to_owned(),
            payload,
            protocol_version: default_protocol_version(),
        }
    }

    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    pub fn from_json(input: &str) -> serde_json::Result<Self> {
        serde_json::from_str(input)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContractRegistry {
    contracts: BTreeMap<String, ContractInfo>,
    stylus_addresses: BTreeSet<String>,
    evm_addresses: BTreeSet<String>,
}

impl ContractRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn normalize_address(address: &str) -> String {
        let address = address.to_ascii_lowercase();
        address.strip_prefix("0x").unwrap_or(&address).to_owned()
    }

    pub fn format_address(address: &str) -> String {
        format!("0x{}", Self::normalize_address(address))
    }

    pub fn register(&mut self, mut contract: ContractInfo) {
        let address = Self::normalize_address(&contract.address);
        contract.address = Self::format_address(&contract.address);
        let is_stylus = contract
            .environment
            .eq_ignore_ascii_case(Environment::Stylus.as_str());
        self.contracts.insert(address.clone(), contract);
        if is_stylus {
            self.stylus_addresses.insert(address.clone());
            self.evm_addresses.remove(&address);
        } else {
            self.evm_addresses.insert(address.clone());
            self.stylus_addresses.remove(&address);
        }
    }

    pub fn unregister(&mut self, address: &str) -> Option<ContractInfo> {
        let address = Self::normalize_address(address);
        self.stylus_addresses.remove(&address);
        self.evm_addresses.remove(&address);
        self.contracts.remove(&address)
    }

    pub fn get(&self, address: &str) -> Option<&ContractInfo> {
        self.contracts.get(&Self::normalize_address(address))
    }

    pub fn is_registered(&self, address: &str) -> bool {
        self.contracts
            .contains_key(&Self::normalize_address(address))
    }

    pub fn is_stylus(&self, address: &str) -> bool {
        self.stylus_addresses
            .contains(&Self::normalize_address(address))
    }

    pub fn is_evm(&self, address: &str) -> bool {
        self.evm_addresses
            .contains(&Self::normalize_address(address))
    }

    pub fn get_environment(&self, address: &str) -> Option<&str> {
        self.get(address)
            .map(|contract| contract.environment.as_str())
    }

    pub fn get_all_contracts(&self) -> Vec<&ContractInfo> {
        self.contracts.values().collect()
    }

    pub fn get_stylus_contracts(&self) -> Vec<&ContractInfo> {
        self.contracts
            .values()
            .filter(|contract| contract.environment.eq_ignore_ascii_case("stylus"))
            .collect()
    }

    pub fn get_evm_contracts(&self) -> Vec<&ContractInfo> {
        self.contracts
            .values()
            .filter(|contract| contract.environment.eq_ignore_ascii_case("evm"))
            .collect()
    }

    pub fn clear(&mut self) {
        self.contracts.clear();
        self.stylus_addresses.clear();
        self.evm_addresses.clear();
    }

    pub fn to_value(&self) -> Value {
        json!({
            "contracts": self.contracts
        })
    }

    pub fn from_value(value: &Value) -> serde_json::Result<Self> {
        let mut registry = Self::new();
        registry.load_from_value(value)?;
        Ok(registry)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let content = serde_json::to_string_pretty(&self.to_value()).map_err(json_to_io_error)?;
        fs::write(path, content)
    }

    pub fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let content = fs::read_to_string(path)?;
        let value = serde_json::from_str::<Value>(&content).map_err(json_to_io_error)?;
        Self::from_value(&value).map_err(json_to_io_error)
    }

    pub fn load_from_file(&mut self, path: impl AsRef<Path>) -> std::io::Result<usize> {
        let content = fs::read_to_string(path)?;
        let value = serde_json::from_str::<Value>(&content).map_err(json_to_io_error)?;
        self.load_from_value(&value).map_err(json_to_io_error)
    }

    pub fn load_from_value(&mut self, value: &Value) -> serde_json::Result<usize> {
        match value.get("contracts") {
            Some(Value::Array(contracts)) => {
                for item in contracts {
                    let contract = serde_json::from_value::<ContractInfo>(item.clone())?;
                    self.register(contract);
                }
                Ok(contracts.len())
            }
            Some(Value::Object(contracts)) => {
                for (address, item) in contracts {
                    let mut item = item.as_object().cloned().unwrap_or_default();
                    item.entry("address".to_owned())
                        .or_insert_with(|| Value::String(address.clone()));
                    let contract = serde_json::from_value::<ContractInfo>(Value::Object(item))?;
                    self.register(contract);
                }
                Ok(contracts.len())
            }
            _ => Ok(0),
        }
    }
}

pub const STYLUS_BYTECODE_PREFIX: &[u8] = &[0xef, 0x00, 0x01];
pub const STYLUS_MARKER_PATTERNS: &[&[u8]] = &[b"\x00asm"];

pub fn detect_stylus_bytecode(bytecode: &[u8]) -> bool {
    if bytecode.len() < 4 {
        return false;
    }

    STYLUS_MARKER_PATTERNS.iter().any(|pattern| {
        bytecode[..bytecode.len().min(100)]
            .windows(pattern.len())
            .any(|window| window == *pattern)
    }) || bytecode.starts_with(STYLUS_BYTECODE_PREFIX)
}

fn json_to_io_error(error: serde_json::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
}

fn default_protocol_version() -> String {
    PROTOCOL_VERSION.to_owned()
}

fn default_environment() -> String {
    Environment::Evm.as_str().to_owned()
}

fn default_call_type() -> String {
    "external".to_owned()
}

fn default_success() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        detect_stylus_bytecode, BridgeMessage, CallArgument, ContractInfo, ContractRegistry,
        CrossEnvCall, CrossEnvTrace, Environment, MessageType, SourceLocation, TraceRequest,
        TraceResponse, PROTOCOL_VERSION,
    };

    #[test]
    fn cross_environment_trace_round_trips_nested_calls() {
        let mut child = CrossEnvCall::new(2, Environment::Stylus.as_str(), "0xstylus", "mint");
        child.parent_call_id = Some(1);
        child.function_signature = Some("mint(address,uint256)".to_owned());
        child.args = vec![
            CallArgument::new("to", "address", "0xabc"),
            CallArgument::new("amount", "uint256", "7"),
        ];
        child.source_location = Some(SourceLocation {
            file: "src/lib.rs".to_owned(),
            line: 42,
            column: Some(9),
        });
        child.cross_env_ref = Some("stylus-trace:0".to_owned());

        let mut root = CrossEnvCall::new(1, Environment::Evm.as_str(), "0xevm", "updateBalance");
        root.function_selector = Some("0x12345678".to_owned());
        root.gas_used = Some(21_000);
        root.children = vec![child.clone()];

        let mut trace = CrossEnvTrace::new("trace-1");
        trace.transaction_hash = Some("0xtx".to_owned());
        trace.root_call = Some(root.clone());
        trace.calls = vec![root, child];
        trace.from_address = Some("0xfrom".to_owned());
        trace.to_address = Some("0xto".to_owned());
        trace.gas_used = Some(30_000);

        let encoded = trace.to_json().expect("serialize trace");
        let decoded = CrossEnvTrace::from_json(&encoded).expect("deserialize trace");

        assert_eq!(decoded.protocol_version, PROTOCOL_VERSION);
        assert_eq!(decoded.root_call.expect("root").children.len(), 1);
        assert_eq!(decoded.calls[1].args[1].value, "7");
    }

    #[test]
    fn protocol_defaults_match_python_bridge_contract() {
        let request = serde_json::from_value::<TraceRequest>(json!({
            "request_id": "req-1"
        }))
        .expect("request defaults");

        assert_eq!(request.target_address, "");
        assert_eq!(request.calldata, "");
        assert_eq!(request.source_environment, "evm");
        assert_eq!(request.value, 0);
        assert_eq!(request.depth, 0);

        let trace = serde_json::from_value::<CrossEnvTrace>(json!({
            "trace_id": "trace-1"
        }))
        .expect("trace defaults");
        assert_eq!(trace.protocol_version, PROTOCOL_VERSION);
        assert!(trace.success);
    }

    #[test]
    fn contract_info_omits_absent_optional_fields() {
        let mut contract = ContractInfo::new("0xabc", Environment::Stylus.as_str(), "StylusToken");
        contract.project_path = Some("/tmp/stylus".to_owned());
        contract.source_files = vec!["src/lib.rs".to_owned()];

        let encoded = serde_json::to_value(&contract).expect("serialize contract");

        assert_eq!(encoded["environment"], "stylus");
        assert_eq!(encoded["source_files"], json!(["src/lib.rs"]));
        assert!(encoded.get("debug_dir").is_none());
        assert!(encoded.get("lib_path").is_none());
    }

    #[test]
    fn trace_response_and_bridge_message_round_trip() {
        let response = TraceResponse::success("req-1", CrossEnvTrace::new("trace-1"));
        let message = BridgeMessage::new(
            MessageType::TraceResponse,
            serde_json::to_value(&response).expect("response payload"),
        );

        let decoded = BridgeMessage::from_json(&message.to_json().expect("message json"))
            .expect("decode message");
        let response =
            serde_json::from_value::<TraceResponse>(decoded.payload).expect("decode response");

        assert_eq!(decoded.message_type, "trace_response");
        assert_eq!(decoded.protocol_version, PROTOCOL_VERSION);
        assert_eq!(response.status, "success");
        assert_eq!(response.trace.expect("trace").trace_id, "trace-1");

        let error = TraceResponse::error("req-2", "missing contract", "not_found");
        let encoded = serde_json::to_value(error).expect("error response");
        assert_eq!(encoded["error_code"], "not_found");
        assert!(encoded.get("trace").is_none());
    }

    #[test]
    fn contract_registry_formats_and_persists_addresses() {
        let mut registry = ContractRegistry::new();
        let mut evm = ContractInfo::new("ABCDEF", Environment::Evm.as_str(), "EVM");
        evm.debug_dir = Some("debug".to_owned());
        let mut stylus = ContractInfo::new("0x1234", Environment::Stylus.as_str(), "Stylus");
        stylus.lib_path = Some("lib.so".to_owned());

        registry.register(evm);
        registry.register(stylus);

        assert!(registry.is_registered("0xabcdef"));
        assert!(registry.is_evm("abcdef"));
        assert!(registry.is_stylus("1234"));
        assert_eq!(registry.get_environment("0x1234"), Some("stylus"));
        assert_eq!(registry.get_evm_contracts()[0].name, "EVM");
        assert_eq!(registry.get_stylus_contracts()[0].name, "Stylus");
        assert_eq!(
            registry.get("ABCDEF").expect("contract").address,
            "0xabcdef"
        );

        let restored = ContractRegistry::from_value(&registry.to_value()).expect("restore");
        assert_eq!(
            restored
                .get("0x1234")
                .expect("restored")
                .lib_path
                .as_deref(),
            Some("lib.so")
        );
    }

    #[test]
    fn contract_registry_loads_list_and_dict_config_formats() {
        let mut registry = ContractRegistry::new();
        let loaded = registry
            .load_from_value(&json!({
                "contracts": [
                    {"address": "0xaaa", "environment": "evm", "name": "A", "debug_dir": "d"},
                    {"address": "0xbbb", "environment": "stylus", "name": "B", "lib_path": "l"}
                ]
            }))
            .expect("load list");

        assert_eq!(loaded, 2);
        assert!(registry.is_evm("aaa"));
        assert!(registry.is_stylus("bbb"));

        let loaded = registry
            .load_from_value(&json!({
                "contracts": {
                    "0xbeef": {"environment": "stylus", "name": "Beef", "project_path": "proj"}
                }
            }))
            .expect("load dict");

        assert_eq!(loaded, 1);
        assert_eq!(
            registry
                .unregister("0xbeef")
                .expect("registered")
                .project_path
                .as_deref(),
            Some("proj")
        );
        registry.clear();
        assert!(registry.get_all_contracts().is_empty());
    }

    #[test]
    fn contract_registry_persists_to_disk() {
        let mut registry = ContractRegistry::new();
        registry.register(ContractInfo::new("0xabc", "evm", "Persisted"));

        let path =
            std::env::temp_dir().join(format!("soldb-bridge-registry-{}.json", std::process::id()));
        registry.save(&path).expect("save registry");
        let restored = ContractRegistry::load(&path).expect("load registry");
        std::fs::remove_file(path).ok();

        assert_eq!(restored.get("abc").expect("contract").name, "Persisted");
    }

    #[test]
    fn register_moves_contract_between_environment_sets() {
        let mut registry = ContractRegistry::new();
        registry.register(ContractInfo::new("0xabc", "evm", "X"));
        assert!(registry.is_evm("0xabc"));
        assert!(!registry.is_stylus("0xabc"));

        registry.register(ContractInfo::new("0xabc", "stylus", "X"));
        assert!(registry.is_stylus("0xabc"));
        assert!(!registry.is_evm("0xabc"));
    }

    #[test]
    fn detects_stylus_bytecode_patterns() {
        assert!(!detect_stylus_bytecode(b""));
        assert!(!detect_stylus_bytecode(b"\x01\x02\x03"));
        assert!(detect_stylus_bytecode(&[0xef, 0x00, 0x01, 0x00]));
        assert!(detect_stylus_bytecode(b"\x00asm\x00\x00\x00\x00"));
        assert!(!detect_stylus_bytecode(&[0x60, 0x80, 0x60, 0x40]));
    }
}
