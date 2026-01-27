"""
Cross-Environment Bridge Client

Client for communicating with the cross-environment debug bridge server.
Used by SolDB to request traces from Stylus contracts.
"""

import json
import uuid
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from .protocol import (
    PROTOCOL_VERSION,
    ContractInfo,
    TraceRequest,
    TraceResponse,
    CrossEnvTrace,
    CrossEnvCall,
)


class BridgeClientError(Exception):
    """Exception raised by bridge client operations."""
    pass


class CrossEnvBridgeClient:
    """
    Client for the Cross-Environment Debug Bridge.

    Used by SolDB to:
    - Register contracts with the bridge
    - Request traces from Stylus contracts
    - Submit EVM traces for Stylus to consume
    """

    def __init__(
        self,
        bridge_url: str = "http://127.0.0.1:8765",
        timeout: int = 30,
    ):
        """
        Args:
            bridge_url: URL of the bridge server
            timeout: Request timeout in seconds
        """
        self.bridge_url = bridge_url.rstrip("/")
        self.timeout = timeout

    def _make_request(
        self,
        method: str,
        path: str,
        data: Optional[Dict] = None,
    ) -> Dict:
        """Make an HTTP request to the bridge server."""
        url = f"{self.bridge_url}{path}"

        if data is not None:
            body = json.dumps(data).encode("utf-8")
            headers = {"Content-Type": "application/json"}
        else:
            body = None
            headers = {}

        req = urllib.request.Request(url, data=body, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                error_body = json.loads(e.read().decode("utf-8"))
                raise BridgeClientError(
                    f"HTTP {e.code}: {error_body.get('error_message', str(e))}"
                )
            except json.JSONDecodeError:
                raise BridgeClientError(f"HTTP {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            raise BridgeClientError(f"Connection failed: {e.reason}")
        except Exception as e:
            raise BridgeClientError(f"Request failed: {e}")

    def health_check(self) -> Dict:
        """Check if the bridge server is healthy."""
        return self._make_request("GET", "/health")

    def is_available(self) -> bool:
        """Check if the bridge server is available."""
        try:
            result = self.health_check()
            return result.get("status") == "healthy"
        except BridgeClientError:
            return False

    def register_contract(self, contract: ContractInfo) -> Dict:
        """Register a contract with the bridge."""
        return self._make_request("POST", "/register", contract.to_dict())

    def register_evm_contract(
        self,
        address: str,
        name: str,
        debug_dir: Optional[str] = None,
    ) -> Dict:
        """Register an EVM contract."""
        contract = ContractInfo(
            address=address,
            environment="evm",
            name=name,
            debug_dir=debug_dir,
        )
        return self.register_contract(contract)

    def register_stylus_contract(
        self,
        address: str,
        name: str,
        lib_path: Optional[str] = None,
    ) -> Dict:
        """Register a Stylus contract."""
        contract = ContractInfo(
            address=address,
            environment="stylus",
            name=name,
            lib_path=lib_path,
        )
        return self.register_contract(contract)

    def unregister_contract(self, address: str) -> Dict:
        """Unregister a contract from the bridge."""
        return self._make_request("DELETE", f"/contract/{address}")

    def get_contract(self, address: str) -> Optional[ContractInfo]:
        """Get contract info by address."""
        try:
            result = self._make_request("GET", f"/contract/{address}")
            return ContractInfo.from_dict(result)
        except BridgeClientError:
            return None

    def list_contracts(self) -> List[ContractInfo]:
        """List all registered contracts."""
        result = self._make_request("GET", "/contracts")
        return [ContractInfo.from_dict(c) for c in result.get("contracts", [])]

    def is_stylus_contract(self, address: str) -> bool:
        """Check if an address is a registered Stylus contract."""
        contract = self.get_contract(address)
        return contract is not None and contract.environment == "stylus"

    def is_evm_contract(self, address: str) -> bool:
        """Check if an address is a registered EVM contract."""
        contract = self.get_contract(address)
        return contract is not None and contract.environment == "evm"

    def request_stylus_trace(
        self,
        target_address: str,
        calldata: str,
        caller_address: Optional[str] = None,
        value: int = 0,
        depth: int = 0,
        parent_call_id: Optional[int] = None,
        parent_trace_id: Optional[str] = None,
        transaction_hash: Optional[str] = None,
        block_number: Optional[int] = None,
        rpc_endpoint: Optional[str] = None,
    ) -> TraceResponse:
        """
        Request a trace from a Stylus contract.

        Args:
            target_address: Address of the Stylus contract
            calldata: Hex-encoded calldata
            caller_address: Address of the caller
            value: ETH value sent with the call
            depth: Current call depth
            parent_call_id: ID of the parent call in SolDB trace
            parent_trace_id: ID of the SolDB trace
            transaction_hash: Transaction hash (if tracing existing tx)
            block_number: Block number for context
            rpc_endpoint: RPC endpoint URL for tx mode

        Returns:
            TraceResponse containing the Stylus trace
        """
        request = TraceRequest(
            request_id=str(uuid.uuid4()),
            transaction_hash=transaction_hash,
            block_number=block_number,
            rpc_endpoint=rpc_endpoint,
            target_address=target_address,
            caller_address=caller_address,
            calldata=calldata,
            value=value,
            depth=depth,
            parent_call_id=parent_call_id,
            parent_trace_id=parent_trace_id,
            source_environment="evm",
        )

        result = self._make_request("POST", "/request-trace", request.to_dict())
        return TraceResponse.from_dict(result)

    def submit_trace(self, trace: CrossEnvTrace) -> Dict:
        """
        Submit a completed trace to the bridge.

        This allows Stylus to request EVM traces when needed.
        """
        return self._make_request("POST", "/submit-trace", trace.to_dict())

    def get_trace(self, trace_id: str) -> Optional[CrossEnvTrace]:
        """Retrieve a trace by ID."""
        try:
            result = self._make_request("GET", f"/trace/{trace_id}")
            return CrossEnvTrace.from_dict(result)
        except BridgeClientError:
            return None


class StylusBridgeIntegration:
    """
    Integration layer for SolDB to communicate with Stylus via the bridge.

    This class provides high-level methods for detecting Stylus contracts
    and fetching their traces during EVM transaction tracing.
    """

    def __init__(
        self,
        bridge_url: Optional[str] = None,
        enabled: bool = True,
    ):
        """
        Args:
            bridge_url: URL of the bridge server (None to auto-detect)
            enabled: Whether cross-env tracing is enabled
        """
        self.enabled = enabled
        self.bridge_url = bridge_url or "http://127.0.0.1:8765"
        self._client: Optional[CrossEnvBridgeClient] = None
        self._connected = False

        # Cache for contract lookups
        self._contract_cache: Dict[str, Optional[ContractInfo]] = {}

    @property
    def client(self) -> CrossEnvBridgeClient:
        """Get or create the bridge client."""
        if self._client is None:
            self._client = CrossEnvBridgeClient(self.bridge_url)
        return self._client

    def connect(self) -> bool:
        """
        Attempt to connect to the bridge server.

        Returns True if connected successfully.
        """
        if not self.enabled:
            return False

        try:
            if self.client.is_available():
                self._connected = True
                return True
        except Exception:
            pass

        self._connected = False
        return False

    @property
    def is_connected(self) -> bool:
        """Check if connected to the bridge."""
        return self._connected and self.enabled

    def _normalize_address(self, address: str) -> str:
        """Normalize address to lowercase with 0x prefix."""
        addr = address.lower()
        if not addr.startswith("0x"):
            addr = "0x" + addr
        return addr

    def is_stylus_contract(self, address: str) -> bool:
        """
        Check if an address is a Stylus contract.

        Uses cached results when available.
        """
        if not self.is_connected:
            return False

        addr = self._normalize_address(address)

        # Check cache first
        if addr in self._contract_cache:
            contract = self._contract_cache[addr]
            return contract is not None and contract.environment == "stylus"

        # Query bridge
        try:
            contract = self.client.get_contract(addr)
            self._contract_cache[addr] = contract
            return contract is not None and contract.environment == "stylus"
        except BridgeClientError:
            return False

    def get_contract_info(self, address: str) -> Optional[ContractInfo]:
        """Get contract info from the bridge."""
        if not self.is_connected:
            return None

        addr = self._normalize_address(address)

        # Check cache
        if addr in self._contract_cache:
            return self._contract_cache[addr]

        # Query bridge
        try:
            contract = self.client.get_contract(addr)
            self._contract_cache[addr] = contract
            return contract
        except BridgeClientError:
            return None

    def request_trace(
        self,
        target_address: str,
        calldata: str,
        caller_address: Optional[str] = None,
        value: int = 0,
        depth: int = 0,
        parent_call_id: Optional[int] = None,
        transaction_hash: Optional[str] = None,
        block_number: Optional[int] = None,
        rpc_endpoint: Optional[str] = None,
    ) -> Optional[CrossEnvTrace]:
        """
        Request a trace from a Stylus contract.

        Returns the trace if successful, None otherwise.
        """
        if not self.is_connected:
            return None

        try:
            response = self.client.request_stylus_trace(
                target_address=target_address,
                calldata=calldata,
                caller_address=caller_address,
                value=value,
                depth=depth,
                parent_call_id=parent_call_id,
                transaction_hash=transaction_hash,
                block_number=block_number,
                rpc_endpoint=rpc_endpoint,
            )

            if response.status == "success" and response.trace:
                return response.trace
            return None
        except BridgeClientError:
            return None

    def clear_cache(self) -> None:
        """Clear the contract cache."""
        self._contract_cache.clear()

    def register_contract(self, contract: ContractInfo) -> bool:
        """Register a contract with the bridge."""
        if not self.is_connected:
            return False

        try:
            self.client.register_contract(contract)
            addr = self._normalize_address(contract.address)
            self._contract_cache[addr] = contract
            return True
        except BridgeClientError:
            return False
