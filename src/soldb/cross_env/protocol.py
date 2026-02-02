"""
Cross-Environment Debug Protocol Definitions

Defines the shared protocol for communication between SolDB (Solidity/EVM)
and StylusDB (Rust/Stylus) debuggers.

Protocol Version: 1.0
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import json

PROTOCOL_VERSION = "1.0"


class Environment(str, Enum):
    """Execution environment type."""
    EVM = "evm"
    STYLUS = "stylus"


@dataclass
class SourceLocation:
    """Source code location for a call."""
    file: str
    line: int
    column: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SourceLocation":
        return cls(
            file=data.get("file", ""),
            line=data.get("line", 0),
            column=data.get("column"),
        )


@dataclass
class CallArgument:
    """Function call argument."""
    name: str
    type: str
    value: str  # String representation of the value

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CallArgument":
        return cls(
            name=data.get("name", ""),
            type=data.get("type", ""),
            value=data.get("value", ""),
        )


@dataclass
class CrossEnvCall:
    """
    Represents a single function call in the cross-environment trace.

    This is the unified call format that both SolDB and StylusDB produce
    and consume.
    """
    call_id: int
    parent_call_id: Optional[int]
    environment: str  # "evm" or "stylus"
    contract_address: str

    # Function info
    function_name: str
    function_selector: Optional[str] = None  # 4-byte selector for EVM
    function_signature: Optional[str] = None  # Full signature

    # Source location (if available)
    source_location: Optional[SourceLocation] = None

    # Arguments and return value
    args: List[CallArgument] = field(default_factory=list)
    return_data: Optional[str] = None  # Hex-encoded return data
    return_value: Optional[str] = None  # Decoded return value (string repr)

    # Execution info
    gas_used: Optional[int] = None
    success: bool = True
    error: Optional[str] = None

    # Call type: "external", "internal", "CALL", "DELEGATECALL", "STATICCALL"
    call_type: str = "external"
    value: Optional[int] = None  # ETH value sent (for CALL)

    # Nested calls
    children: List["CrossEnvCall"] = field(default_factory=list)

    # Cross-environment reference
    # When this call crosses to another environment, this contains
    # the trace ID and root call ID from the other environment
    cross_env_ref: Optional[str] = None  # Format: "trace_id:call_id"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "call_id": self.call_id,
            "parent_call_id": self.parent_call_id,
            "environment": self.environment,
            "contract_address": self.contract_address,
            "function_name": self.function_name,
            "call_type": self.call_type,
            "success": self.success,
            "children": [c.to_dict() for c in self.children],
        }

        # Add optional fields if present
        if self.function_selector:
            result["function_selector"] = self.function_selector
        if self.function_signature:
            result["function_signature"] = self.function_signature
        if self.source_location:
            result["source_location"] = self.source_location.to_dict()
        if self.args:
            result["args"] = [a.to_dict() for a in self.args]
        if self.return_data:
            result["return_data"] = self.return_data
        if self.return_value:
            result["return_value"] = self.return_value
        if self.gas_used is not None:
            result["gas_used"] = self.gas_used
        if self.error:
            result["error"] = self.error
        if self.value is not None:
            result["value"] = self.value
        if self.cross_env_ref:
            result["cross_env_ref"] = self.cross_env_ref

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CrossEnvCall":
        """Create from dictionary."""
        source_loc = None
        if "source_location" in data and data["source_location"]:
            source_loc = SourceLocation.from_dict(data["source_location"])

        args = [CallArgument.from_dict(a) for a in data.get("args", [])]
        children = [cls.from_dict(c) for c in data.get("children", [])]

        return cls(
            call_id=data.get("call_id", 0),
            parent_call_id=data.get("parent_call_id"),
            environment=data.get("environment", "evm"),
            contract_address=data.get("contract_address", ""),
            function_name=data.get("function_name", ""),
            function_selector=data.get("function_selector"),
            function_signature=data.get("function_signature"),
            source_location=source_loc,
            args=args,
            return_data=data.get("return_data"),
            return_value=data.get("return_value"),
            gas_used=data.get("gas_used"),
            success=data.get("success", True),
            error=data.get("error"),
            call_type=data.get("call_type", "external"),
            value=data.get("value"),
            children=children,
            cross_env_ref=data.get("cross_env_ref"),
        )


@dataclass
class CrossEnvTrace:
    """
    Complete cross-environment trace for a transaction.

    Contains all calls across both EVM and Stylus environments,
    maintaining the full call hierarchy.
    """
    trace_id: str
    protocol_version: str = PROTOCOL_VERSION
    transaction_hash: Optional[str] = None

    # Root call (entry point of the transaction)
    root_call: Optional[CrossEnvCall] = None

    # Flat list of all calls (for easy lookup)
    calls: List[CrossEnvCall] = field(default_factory=list)

    # Metadata
    from_address: Optional[str] = None
    to_address: Optional[str] = None
    value: Optional[int] = None
    gas_used: Optional[int] = None
    success: bool = True
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "trace_id": self.trace_id,
            "protocol_version": self.protocol_version,
            "success": self.success,
        }

        if self.transaction_hash:
            result["transaction_hash"] = self.transaction_hash
        if self.root_call:
            result["root_call"] = self.root_call.to_dict()
        if self.calls:
            result["calls"] = [c.to_dict() for c in self.calls]
        if self.from_address:
            result["from_address"] = self.from_address
        if self.to_address:
            result["to_address"] = self.to_address
        if self.value is not None:
            result["value"] = self.value
        if self.gas_used is not None:
            result["gas_used"] = self.gas_used
        if self.error:
            result["error"] = self.error

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CrossEnvTrace":
        """Create from dictionary."""
        root_call = None
        if "root_call" in data and data["root_call"]:
            root_call = CrossEnvCall.from_dict(data["root_call"])

        calls = [CrossEnvCall.from_dict(c) for c in data.get("calls", [])]

        return cls(
            trace_id=data.get("trace_id", ""),
            protocol_version=data.get("protocol_version", PROTOCOL_VERSION),
            transaction_hash=data.get("transaction_hash"),
            root_call=root_call,
            calls=calls,
            from_address=data.get("from_address"),
            to_address=data.get("to_address"),
            value=data.get("value"),
            gas_used=data.get("gas_used"),
            success=data.get("success", True),
            error=data.get("error"),
        )

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> "CrossEnvTrace":
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class ContractInfo:
    """Information about a registered contract."""
    address: str
    environment: str  # "evm" or "stylus"
    name: str

    # Debug info paths
    debug_dir: Optional[str] = None  # For EVM (ethdebug directory)
    lib_path: Optional[str] = None   # For Stylus (.dylib/.so path)
    project_path: Optional[str] = None  # For Stylus (path to project directory)

    # Optional metadata
    compiler_version: Optional[str] = None
    source_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "address": self.address,
            "environment": self.environment,
            "name": self.name,
        }
        if self.debug_dir:
            result["debug_dir"] = self.debug_dir
        if self.lib_path:
            result["lib_path"] = self.lib_path
        if self.project_path:
            result["project_path"] = self.project_path
        if self.compiler_version:
            result["compiler_version"] = self.compiler_version
        if self.source_files:
            result["source_files"] = self.source_files
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractInfo":
        return cls(
            address=data.get("address", ""),
            environment=data.get("environment", "evm"),
            name=data.get("name", ""),
            debug_dir=data.get("debug_dir"),
            lib_path=data.get("lib_path"),
            project_path=data.get("project_path"),
            compiler_version=data.get("compiler_version"),
            source_files=data.get("source_files", []),
        )


@dataclass
class TraceRequest:
    """
    Request for trace from another environment.

    Sent when one debugger detects a cross-environment call and needs
    the trace from the other environment.
    """
    request_id: str

    # Transaction context
    transaction_hash: Optional[str] = None
    block_number: Optional[int] = None
    rpc_endpoint: Optional[str] = None

    # Call context
    target_address: str = ""
    caller_address: Optional[str] = None
    calldata: str = ""
    value: int = 0

    # Call hierarchy context
    depth: int = 0
    parent_call_id: Optional[int] = None
    parent_trace_id: Optional[str] = None

    # Requesting environment
    source_environment: str = "evm"  # Which environment is requesting

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "transaction_hash": self.transaction_hash,
            "block_number": self.block_number,
            "rpc_endpoint": self.rpc_endpoint,
            "target_address": self.target_address,
            "caller_address": self.caller_address,
            "calldata": self.calldata,
            "value": self.value,
            "depth": self.depth,
            "parent_call_id": self.parent_call_id,
            "parent_trace_id": self.parent_trace_id,
            "source_environment": self.source_environment,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TraceRequest":
        return cls(
            request_id=data.get("request_id", ""),
            transaction_hash=data.get("transaction_hash"),
            block_number=data.get("block_number"),
            rpc_endpoint=data.get("rpc_endpoint"),
            target_address=data.get("target_address", ""),
            caller_address=data.get("caller_address"),
            calldata=data.get("calldata", ""),
            value=data.get("value", 0),
            depth=data.get("depth", 0),
            parent_call_id=data.get("parent_call_id"),
            parent_trace_id=data.get("parent_trace_id"),
            source_environment=data.get("source_environment", "evm"),
        )


@dataclass
class TraceResponse:
    """
    Response containing trace from the requested environment.
    """
    request_id: str
    status: str  # "success", "error", "not_found"

    # The trace data
    trace: Optional[CrossEnvTrace] = None

    # Error information
    error_message: Optional[str] = None
    error_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "request_id": self.request_id,
            "status": self.status,
        }
        if self.trace:
            result["trace"] = self.trace.to_dict()
        if self.error_message:
            result["error_message"] = self.error_message
        if self.error_code:
            result["error_code"] = self.error_code
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TraceResponse":
        trace = None
        if "trace" in data and data["trace"]:
            trace = CrossEnvTrace.from_dict(data["trace"])
        return cls(
            request_id=data.get("request_id", ""),
            status=data.get("status", "error"),
            trace=trace,
            error_message=data.get("error_message"),
            error_code=data.get("error_code"),
        )


# Message types for the bridge protocol
class MessageType(str, Enum):
    """Types of messages in the bridge protocol."""
    HANDSHAKE = "handshake"
    REGISTER_CONTRACT = "register_contract"
    UNREGISTER_CONTRACT = "unregister_contract"
    TRACE_REQUEST = "trace_request"
    TRACE_RESPONSE = "trace_response"
    SUBMIT_TRACE = "submit_trace"
    GET_CONTRACTS = "get_contracts"
    HEALTH_CHECK = "health_check"


@dataclass
class BridgeMessage:
    """Generic bridge protocol message wrapper."""
    message_type: str
    payload: Dict[str, Any]
    protocol_version: str = PROTOCOL_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_type": self.message_type,
            "payload": self.payload,
            "protocol_version": self.protocol_version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BridgeMessage":
        return cls(
            message_type=data.get("message_type", ""),
            payload=data.get("payload", {}),
            protocol_version=data.get("protocol_version", PROTOCOL_VERSION),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> "BridgeMessage":
        return cls.from_dict(json.loads(json_str))
