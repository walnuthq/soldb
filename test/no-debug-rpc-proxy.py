#!/usr/bin/env python3
"""Forward JSON-RPC requests while making debug_traceTransaction unavailable."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer


class NoDebugProxy(BaseHTTPRequestHandler):
    upstream = ""

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self.send_json({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            return

        if isinstance(payload, list):
            if any(item.get("method") == "debug_traceTransaction" for item in payload if isinstance(item, dict)):
                responses = []
                for item in payload:
                    if isinstance(item, dict) and item.get("method") == "debug_traceTransaction":
                        responses.append(self.debug_trace_unavailable_response(item))
                    else:
                        responses.append(self.forward_json_payload(item))
                self.send_json(responses)
                return
        elif payload.get("method") == "debug_traceTransaction":
            self.send_json(
                self.debug_trace_unavailable_response(payload)
            )
            return

        request = urllib.request.Request(
            self.upstream,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                upstream_body = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            upstream_body = error.read()
            status = error.code

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(upstream_body)))
        self.end_headers()
        self.wfile.write(upstream_body)

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def send_json(self, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def debug_trace_unavailable_response(self, payload: dict) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "error": {"code": -32601, "message": "method not found"},
        }

    def forward_json_payload(self, payload: object) -> object:
        request_body = json.dumps(payload).encode()
        request = urllib.request.Request(
            self.upstream,
            data=request_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            return json.loads(error.read())


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: no-debug-rpc-proxy.py <upstream-rpc-url> <url-output-file>", file=sys.stderr)
        return 2

    NoDebugProxy.upstream = sys.argv[1]
    server = HTTPServer(("127.0.0.1", 0), NoDebugProxy)
    with open(sys.argv[2], "w", encoding="utf-8") as output:
        output.write(f"http://127.0.0.1:{server.server_port}\n")
        output.flush()
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
