use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use soldb_core::TransactionTrace;

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
    #[serde(default)]
    pub address: String,
    #[serde(default = "default_environment")]
    pub environment: String,
    #[serde(default)]
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
    #[serde(default)]
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TraceStore {
    traces: BTreeMap<String, CrossEnvTrace>,
    pending_requests: BTreeMap<String, TraceRequest>,
}

impl TraceStore {
    pub fn store_trace(&mut self, trace: CrossEnvTrace) {
        self.traces.insert(trace.trace_id.clone(), trace);
    }

    pub fn get_trace(&self, trace_id: &str) -> Option<&CrossEnvTrace> {
        self.traces.get(trace_id)
    }

    pub fn add_pending_request(&mut self, request: TraceRequest) {
        self.pending_requests
            .insert(request.request_id.clone(), request);
    }

    pub fn complete_request(&mut self, response: &TraceResponse) -> bool {
        if self.pending_requests.remove(&response.request_id).is_none() {
            return false;
        }
        if let Some(trace) = &response.trace {
            self.store_trace(trace.clone());
        }
        true
    }

    pub fn pending_count(&self) -> usize {
        self.pending_requests.len()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub body: Value,
}

impl HttpResponse {
    pub fn ok(body: Value) -> Self {
        Self {
            status_code: 200,
            body,
        }
    }

    pub fn error(message: impl Into<String>, status_code: u16) -> Self {
        Self {
            status_code,
            body: json!({"error": message.into()}),
        }
    }

    fn reason(&self) -> &'static str {
        match self.status_code {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            _ => "Internal Server Error",
        }
    }

    fn to_http_response(&self) -> String {
        let body = serde_json::to_string(&self.body).unwrap_or_else(|error| {
            json!({"error": format!("Failed to encode response: {error}")}).to_string()
        });
        format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.status_code,
            self.reason(),
            body.len(),
            body
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BridgeHttpHandler {
    pub registry: ContractRegistry,
    pub trace_store: TraceStore,
}

impl BridgeHttpHandler {
    pub fn new(registry: ContractRegistry) -> Self {
        Self {
            registry,
            trace_store: TraceStore::default(),
        }
    }

    pub fn handle_request(&mut self, method: &str, path: &str, body: Option<&str>) -> HttpResponse {
        let path = path.split('?').next().unwrap_or(path);
        match (method, path) {
            ("GET", "/") => self.handle_info(),
            ("GET", "/health") => self.handle_health(),
            ("GET", "/contracts") => self.handle_list_contracts(),
            ("POST", "/register") => self.handle_register_contract(body),
            ("POST", "/request-trace") => self.handle_trace_request(body),
            ("POST", "/submit-trace") => self.handle_submit_trace(body),
            ("POST", "/respond-trace") => self.handle_trace_response(body),
            _ if method == "GET" && path.starts_with("/contract/") => {
                self.handle_get_contract(path.trim_start_matches("/contract/"))
            }
            _ if method == "GET" && path.starts_with("/trace/") => {
                self.handle_get_trace(path.trim_start_matches("/trace/"))
            }
            _ if method == "DELETE" && path.starts_with("/contract/") => {
                self.handle_unregister_contract(path.trim_start_matches("/contract/"))
            }
            _ => HttpResponse::error("Not found", 404),
        }
    }

    fn handle_info(&self) -> HttpResponse {
        HttpResponse::ok(json!({
            "name": "Cross-Environment Debug Bridge",
            "protocol_version": PROTOCOL_VERSION,
            "endpoints": [
                "GET /health",
                "GET /contracts",
                "GET /contract/{address}",
                "GET /trace/{trace_id}",
                "POST /register",
                "POST /request-trace",
                "POST /submit-trace",
                "POST /respond-trace",
                "DELETE /contract/{address}"
            ]
        }))
    }

    fn handle_health(&self) -> HttpResponse {
        HttpResponse::ok(json!({
            "status": "healthy",
            "protocol_version": PROTOCOL_VERSION,
            "contracts_registered": self.registry.get_all_contracts().len(),
            "pending_trace_requests": self.trace_store.pending_count(),
        }))
    }

    fn handle_list_contracts(&self) -> HttpResponse {
        HttpResponse::ok(json!({
            "contracts": self.registry.get_all_contracts(),
            "count": self.registry.get_all_contracts().len(),
        }))
    }

    fn handle_get_contract(&self, address: &str) -> HttpResponse {
        match self.registry.get(address) {
            Some(contract) => HttpResponse::ok(json!(contract)),
            None => HttpResponse::error(format!("Contract not found: {address}"), 404),
        }
    }

    fn handle_register_contract(&mut self, body: Option<&str>) -> HttpResponse {
        let Some(body) = body else {
            return HttpResponse::error("Invalid JSON body", 400);
        };
        let contract = match serde_json::from_str::<ContractInfo>(body) {
            Ok(contract) => contract,
            Err(error) => {
                return HttpResponse::error(format!("Failed to register contract: {error}"), 400)
            }
        };
        if contract.address.is_empty() {
            return HttpResponse::error("Address is required", 400);
        }
        if contract.environment.is_empty() {
            return HttpResponse::error("Environment is required (evm or stylus)", 400);
        }

        let mut registered_contract = contract.clone();
        registered_contract.address =
            ContractRegistry::format_address(&registered_contract.address);
        self.registry.register(contract);
        HttpResponse::ok(json!({
            "status": "registered",
            "contract": registered_contract,
        }))
    }

    fn handle_unregister_contract(&mut self, address: &str) -> HttpResponse {
        if self.registry.unregister(address).is_some() {
            HttpResponse::ok(json!({
                "status": "unregistered",
                "address": address,
            }))
        } else {
            HttpResponse::error(format!("Contract not found: {address}"), 404)
        }
    }

    fn handle_trace_request(&mut self, body: Option<&str>) -> HttpResponse {
        let Some(body) = body else {
            return HttpResponse::error("Invalid JSON body", 400);
        };
        let mut request = match serde_json::from_str::<TraceRequest>(body) {
            Ok(request) => request,
            Err(error) => {
                return HttpResponse::error(
                    format!("Failed to process trace request: {error}"),
                    400,
                )
            }
        };
        if request.request_id.is_empty() {
            request.request_id = generated_id("trace-request");
        }

        let Some(target_contract) = self.registry.get(&request.target_address).cloned() else {
            return HttpResponse {
                status_code: 404,
                body: json!({
                    "status": "error",
                    "error_message": format!("Contract not registered: {}", request.target_address),
                }),
            };
        };

        if target_contract
            .environment
            .eq_ignore_ascii_case(Environment::Evm.as_str())
        {
            return match invoke_evm_trace(&request, &target_contract) {
                Ok(trace) => {
                    self.trace_store.store_trace(trace.clone());
                    let status = if trace.success { "success" } else { "error" };
                    HttpResponse::ok(json!(TraceResponse {
                        request_id: request.request_id,
                        status: status.to_owned(),
                        trace: Some(trace),
                        error_message: None,
                        error_code: None,
                    }))
                }
                Err(error) => {
                    self.trace_store.add_pending_request(request.clone());
                    HttpResponse::ok(json!({
                        "request_id": request.request_id,
                        "status": "pending",
                        "message": format!("Request queued for evm environment (EVM trace generation failed: {error})"),
                        "target_environment": target_contract.environment,
                    }))
                }
            };
        }

        self.trace_store.add_pending_request(request.clone());
        HttpResponse::ok(json!({
            "request_id": request.request_id,
            "status": "pending",
            "message": format!("Request queued for {} environment", target_contract.environment),
            "target_environment": target_contract.environment,
        }))
    }

    fn handle_submit_trace(&mut self, body: Option<&str>) -> HttpResponse {
        let Some(body) = body else {
            return HttpResponse::error("Invalid JSON body", 400);
        };
        let mut trace = match serde_json::from_str::<CrossEnvTrace>(body) {
            Ok(trace) => trace,
            Err(error) => {
                return HttpResponse::error(format!("Failed to store trace: {error}"), 400)
            }
        };
        if trace.trace_id.is_empty() {
            trace.trace_id = generated_id("trace");
        }
        let trace_id = trace.trace_id.clone();
        self.trace_store.store_trace(trace);
        HttpResponse::ok(json!({
            "status": "stored",
            "trace_id": trace_id,
        }))
    }

    fn handle_trace_response(&mut self, body: Option<&str>) -> HttpResponse {
        let Some(body) = body else {
            return HttpResponse::error("Invalid JSON body", 400);
        };
        let response = match serde_json::from_str::<TraceResponse>(body) {
            Ok(response) => response,
            Err(error) => {
                return HttpResponse::error(
                    format!("Failed to process trace response: {error}"),
                    400,
                )
            }
        };

        if self.trace_store.complete_request(&response) {
            HttpResponse::ok(json!({
                "status": "completed",
                "request_id": response.request_id,
            }))
        } else {
            HttpResponse::ok(json!({
                "status": "not_found",
                "message": format!("No pending request found: {}", response.request_id),
            }))
        }
    }

    fn handle_get_trace(&self, trace_id: &str) -> HttpResponse {
        match self.trace_store.get_trace(trace_id) {
            Some(trace) => HttpResponse::ok(json!(trace)),
            None => HttpResponse {
                status_code: 404,
                body: json!({
                    "status": "error",
                    "error_message": format!("Trace not found: {trace_id}"),
                }),
            },
        }
    }
}

fn invoke_evm_trace(
    request: &TraceRequest,
    contract: &ContractInfo,
) -> Result<CrossEnvTrace, String> {
    let rpc_endpoint = request
        .rpc_endpoint
        .as_deref()
        .unwrap_or("http://localhost:8545");
    let simulate_request = soldb_rpc::SimulateCallRequest {
        from_addr: request.caller_address.clone().unwrap_or_else(zero_address),
        to_addr: contract.address.clone(),
        calldata: if request.calldata.is_empty() {
            "0x".to_owned()
        } else {
            request.calldata.clone()
        },
        value: request.value.to_string(),
        block: request.block_number,
        tx_index: None,
    };
    let trace = soldb_rpc::simulate_call(rpc_endpoint, &simulate_request)
        .map_err(|error| error.to_string())?;
    Ok(transaction_trace_to_cross_env(trace, request, contract))
}

fn transaction_trace_to_cross_env(
    trace: TransactionTrace,
    request: &TraceRequest,
    contract: &ContractInfo,
) -> CrossEnvTrace {
    let selector = trace
        .input_data
        .trim_start_matches("0x")
        .get(..8)
        .filter(|selector| !selector.is_empty())
        .map(|selector| format!("0x{}", selector.to_ascii_lowercase()));
    let function_name = selector.as_deref().map_or_else(
        || "runtime_dispatcher".to_owned(),
        |selector| format!("function_{selector}"),
    );

    let mut root_call = CrossEnvCall::new(
        0,
        Environment::Evm.as_str(),
        contract.address.clone(),
        function_name,
    );
    root_call.function_selector = selector;
    root_call.call_type = "entry".to_owned();
    root_call.gas_used = Some(trace.gas_used);
    root_call.return_data = Some(trace.output.clone());
    root_call.success = trace.success;
    root_call.error = trace.error.clone();
    root_call.value = Some(request.value);

    let mut cross_trace = CrossEnvTrace::new(request.request_id.clone());
    cross_trace.transaction_hash = request.transaction_hash.clone();
    cross_trace.root_call = Some(root_call.clone());
    cross_trace.calls = vec![root_call];
    cross_trace.from_address = Some(trace.from_addr);
    cross_trace.to_address = trace.to_addr.or_else(|| Some(contract.address.clone()));
    cross_trace.value = Some(request.value);
    cross_trace.gas_used = Some(trace.gas_used);
    cross_trace.success = trace.success;
    cross_trace.error = trace.error;
    cross_trace
}

fn generated_id(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{prefix}-{}-{nanos}", std::process::id())
}

fn zero_address() -> String {
    "0x0000000000000000000000000000000000000000".to_owned()
}

pub fn run_bridge_server(
    host: &str,
    port: u16,
    verbose: bool,
    config_file: Option<&str>,
) -> std::io::Result<()> {
    let mut registry = ContractRegistry::new();
    if let Some(config_file) = config_file {
        match registry.load_from_file(config_file) {
            Ok(count) if verbose => {
                eprintln!("[Bridge] Loaded {count} contracts from {config_file}")
            }
            Ok(_) => {}
            Err(error) => eprintln!("[Bridge] Warning: Failed to load config: {error}"),
        }
    }

    if verbose {
        print_bridge_banner(host, port);
    }

    let listener = TcpListener::bind(format!("{host}:{port}"))?;
    let mut handler = BridgeHttpHandler::new(registry);
    for stream in listener.incoming() {
        handle_tcp_connection(&mut handler, stream?)?;
    }
    Ok(())
}

fn print_bridge_banner(host: &str, port: u16) {
    println!("Cross-Environment Debug Bridge");
    println!("{}", "=".repeat(40));
    println!("URL: http://{host}:{port}");
    println!("Protocol: {PROTOCOL_VERSION}");
    println!();
    println!("Endpoints:");
    println!("  GET  /health           - Health check");
    println!("  GET  /contracts        - List registered contracts");
    println!("  POST /register         - Register a contract");
    println!("  POST /request-trace    - Request trace from environment");
    println!("  POST /submit-trace     - Submit completed trace");
    println!();
    println!("Press Ctrl+C to stop");
    println!("{}", "=".repeat(40));
}

fn handle_tcp_connection(
    handler: &mut BridgeHttpHandler,
    mut stream: TcpStream,
) -> std::io::Result<()> {
    let request = read_http_request(&mut stream)?;
    let response = match parse_http_request(&request) {
        Some((method, path, body)) => handler.handle_request(method, path, body),
        None => HttpResponse::error("Invalid HTTP request", 400),
    };
    stream.write_all(response.to_http_response().as_bytes())
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut data = Vec::new();
    let mut buffer = [0_u8; 512];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..read]);

        if let Some(header_end) = find_header_end(&data) {
            let headers = String::from_utf8_lossy(&data[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim())
                    })
                })
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            let body_len = data.len().saturating_sub(header_end + 4);
            if body_len >= content_length {
                break;
            }
        }
    }
    String::from_utf8(data)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn parse_http_request(request: &str) -> Option<(&str, &str, Option<&str>)> {
    let (head, body) = request.split_once("\r\n\r\n")?;
    let request_line = head.lines().next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    Some((method, path, (!body.is_empty()).then_some(body)))
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
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
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use serde_json::json;

    use super::{
        detect_stylus_bytecode, handle_tcp_connection, parse_http_request, BridgeHttpHandler,
        BridgeMessage, CallArgument, ContractInfo, ContractRegistry, CrossEnvCall, CrossEnvTrace,
        Environment, MessageType, SourceLocation, TraceRequest, TraceResponse, PROTOCOL_VERSION,
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
    fn protocol_defaults_match_bridge_contract() {
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

    #[test]
    fn bridge_http_handler_serves_health_and_info() {
        let mut handler = BridgeHttpHandler::default();

        let info = handler.handle_request("GET", "/", None);
        assert_eq!(info.status_code, 200);
        assert_eq!(info.body["protocol_version"], PROTOCOL_VERSION);
        assert!(info.body["endpoints"]
            .as_array()
            .expect("endpoints")
            .contains(&json!("GET /health")));

        let health = handler.handle_request("GET", "/health", None);
        assert_eq!(health.status_code, 200);
        assert_eq!(health.body["status"], "healthy");
        assert_eq!(health.body["contracts_registered"], 0);
    }

    #[test]
    fn bridge_http_handler_registers_lists_gets_and_deletes_contracts() {
        let mut handler = BridgeHttpHandler::default();
        let body = json!({
            "address": "ABCDEF",
            "environment": "stylus",
            "name": "Stylus",
            "project_path": "proj"
        })
        .to_string();

        let registered = handler.handle_request("POST", "/register", Some(&body));
        assert_eq!(registered.status_code, 200);
        assert_eq!(registered.body["status"], "registered");
        assert_eq!(registered.body["contract"]["address"], "0xabcdef");

        let listed = handler.handle_request("GET", "/contracts", None);
        assert_eq!(listed.body["count"], 1);
        assert_eq!(listed.body["contracts"][0]["environment"], "stylus");

        let fetched = handler.handle_request("GET", "/contract/0xabcdef", None);
        assert_eq!(fetched.status_code, 200);
        assert_eq!(fetched.body["name"], "Stylus");

        let deleted = handler.handle_request("DELETE", "/contract/abcdef", None);
        assert_eq!(deleted.status_code, 200);
        assert_eq!(deleted.body["status"], "unregistered");

        let missing = handler.handle_request("GET", "/contract/abcdef", None);
        assert_eq!(missing.status_code, 404);
    }

    #[test]
    fn bridge_http_handler_reports_bad_json_and_missing_trace_targets() {
        let mut handler = BridgeHttpHandler::default();

        let bad = handler.handle_request("POST", "/register", Some("{"));
        assert_eq!(bad.status_code, 400);
        assert!(bad.body["error"]
            .as_str()
            .expect("error")
            .contains("Failed to register contract"));

        let trace = handler.handle_request(
            "POST",
            "/request-trace",
            Some(r#"{"request_id":"req-1","target_address":"0xdead"}"#),
        );
        assert_eq!(trace.status_code, 404);
        assert_eq!(trace.body["status"], "error");
        assert!(trace.body["error_message"]
            .as_str()
            .expect("error")
            .contains("Contract not registered"));

        let missing_address = handler.handle_request("POST", "/register", Some("{}"));
        assert_eq!(missing_address.status_code, 400);
        assert_eq!(missing_address.body["error"], "Address is required");

        let unknown = handler.handle_request("GET", "/unknown", None);
        assert_eq!(unknown.status_code, 404);
    }

    #[test]
    fn bridge_http_handler_stores_pending_and_completed_traces() {
        let mut handler = BridgeHttpHandler::default();
        handler.registry.register(ContractInfo::new(
            "0xabc",
            Environment::Stylus.as_str(),
            "Stylus",
        ));

        let request = json!({
            "request_id": "req-1",
            "target_address": "0xabc",
            "caller_address": "0x1",
            "calldata": "0x1234",
        })
        .to_string();
        let queued = handler.handle_request("POST", "/request-trace", Some(&request));
        assert_eq!(queued.status_code, 200);
        assert_eq!(queued.body["status"], "pending");
        assert_eq!(queued.body["target_environment"], "stylus");
        assert_eq!(handler.trace_store.pending_count(), 1);

        let trace = sample_cross_env_trace("trace-1");
        let response = TraceResponse::success("req-1", trace.clone());
        let completed = handler.handle_request(
            "POST",
            "/respond-trace",
            Some(&serde_json::to_string(&response).expect("response json")),
        );
        assert_eq!(completed.status_code, 200);
        assert_eq!(completed.body["status"], "completed");
        assert_eq!(handler.trace_store.pending_count(), 0);

        let fetched = handler.handle_request("GET", "/trace/trace-1", None);
        assert_eq!(fetched.status_code, 200);
        assert_eq!(fetched.body["trace_id"], "trace-1");

        let not_found = handler.handle_request(
            "POST",
            "/respond-trace",
            Some(r#"{"request_id":"missing","status":"success"}"#),
        );
        assert_eq!(not_found.status_code, 200);
        assert_eq!(not_found.body["status"], "not_found");
    }

    #[test]
    fn bridge_http_handler_submits_and_fetches_traces() {
        let mut handler = BridgeHttpHandler::default();
        let trace = sample_cross_env_trace("submitted-trace");
        let submitted = handler.handle_request(
            "POST",
            "/submit-trace",
            Some(&trace.to_json().expect("trace json")),
        );
        assert_eq!(submitted.status_code, 200);
        assert_eq!(submitted.body["status"], "stored");
        assert_eq!(submitted.body["trace_id"], "submitted-trace");

        let fetched = handler.handle_request("GET", "/trace/submitted-trace", None);
        assert_eq!(fetched.status_code, 200);
        assert_eq!(fetched.body["calls"][0]["function_name"], "run");

        let missing = handler.handle_request("GET", "/trace/missing", None);
        assert_eq!(missing.status_code, 404);
        assert_eq!(missing.body["status"], "error");
    }

    #[test]
    fn bridge_http_handler_invokes_evm_trace_from_rpc() {
        let rpc_url = start_bridge_rpc_server();
        let mut handler = BridgeHttpHandler::default();
        handler.registry.register(ContractInfo::new(
            "0x0000000000000000000000000000000000000002",
            Environment::Evm.as_str(),
            "EvmContract",
        ));

        let request = json!({
            "request_id": "req-evm",
            "target_address": "0x0000000000000000000000000000000000000002",
            "caller_address": "0x0000000000000000000000000000000000000001",
            "calldata": "0x12345678",
            "rpc_endpoint": rpc_url,
            "value": 7
        })
        .to_string();
        let response = handler.handle_request("POST", "/request-trace", Some(&request));

        assert_eq!(response.status_code, 200);
        assert_eq!(response.body["request_id"], "req-evm");
        assert_eq!(response.body["status"], "success");
        assert_eq!(response.body["trace"]["trace_id"], "req-evm");
        assert_eq!(
            response.body["trace"]["from_address"],
            "0x0000000000000000000000000000000000000001"
        );
        assert_eq!(response.body["trace"]["root_call"]["environment"], "evm");
        assert_eq!(
            response.body["trace"]["root_call"]["function_selector"],
            "0x12345678"
        );
        assert_eq!(response.body["trace"]["root_call"]["gas_used"], 42_000);

        let fetched = handler.handle_request("GET", "/trace/req-evm", None);
        assert_eq!(fetched.status_code, 200);
        assert_eq!(fetched.body["trace_id"], "req-evm");
    }

    #[test]
    fn parses_http_request_line_and_body() {
        let request = concat!(
            "POST /register HTTP/1.1\r\n",
            "Host: localhost\r\n",
            "Content-Length: 13\r\n",
            "\r\n",
            "{\"name\":\"C\"}"
        );
        let (method, path, body) = parse_http_request(request).expect("parse request");

        assert_eq!(method, "POST");
        assert_eq!(path, "/register");
        assert_eq!(body, Some("{\"name\":\"C\"}"));
    }

    #[test]
    fn bridge_tcp_connection_returns_json_response() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind bridge test server");
        let address = listener.local_addr().expect("local addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            let mut handler = BridgeHttpHandler::default();
            handle_tcp_connection(&mut handler, stream).expect("handle request");
        });

        let mut client = TcpStream::connect(address).expect("connect client");
        client
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write request");
        let mut response = String::new();
        client.read_to_string(&mut response).expect("read response");
        server.join().expect("join server");

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"status\":\"healthy\""));
    }

    fn sample_cross_env_trace(trace_id: &str) -> CrossEnvTrace {
        let root = CrossEnvCall::new(0, Environment::Stylus.as_str(), "0xabc", "run");
        let mut trace = CrossEnvTrace::new(trace_id);
        trace.root_call = Some(root.clone());
        trace.calls = vec![root];
        trace
    }

    fn start_bridge_rpc_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind rpc server");
        let address = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept rpc request");
            respond_to_bridge_rpc_request(stream);
        });
        format!("http://{address}")
    }

    fn respond_to_bridge_rpc_request(mut stream: TcpStream) {
        let request = read_test_http_request(&mut stream);
        let response = if request.contains("\"debug_traceCall\"") {
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "gas": 42000,
                    "returnValue": "2a",
                    "failed": false,
                    "structLogs": [
                        {"pc": 0, "op": "PUSH1", "gas": 100, "gasCost": 3, "depth": 0, "stack": []},
                        {"pc": 1, "op": "STOP", "gas": 97, "gasCost": 0, "depth": 0, "stack": ["0x01"]}
                    ]
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
        stream
            .write_all(http_response.as_bytes())
            .expect("write response");
    }

    fn read_test_http_request(stream: &mut TcpStream) -> String {
        let mut data = Vec::new();
        let mut buffer = [0_u8; 512];
        loop {
            let read = stream.read(&mut buffer).expect("read request");
            if read == 0 {
                break;
            }
            data.extend_from_slice(&buffer[..read]);

            if let Some(header_end) = data.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&data[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                let body_len = data.len().saturating_sub(header_end + 4);
                if body_len >= content_length {
                    break;
                }
            }
        }
        String::from_utf8(data).expect("utf8 request")
    }
}
