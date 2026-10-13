"""Drives soldb-dap-server over stdio and prints the stack after every stop.

usage: dap-session.py SERVER TRACE CONTRACTS [next | continue | break FILE:LINE]...

Launches TRACE with the CONTRACTS mapping, then runs each command. Every stop prints
`stopped: <reason>`, then one `frame: <name> <source>:<line>` line per frame, innermost
first.
"""
import json
import subprocess
import sys

server, trace, contracts, *commands = sys.argv[1:]
proc = subprocess.Popen([server], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
seq = 0


def send(command, arguments=None):
    """Sends one request; returns its response body, printing stop events on the way."""
    global seq
    seq += 1
    body = json.dumps({"seq": seq, "type": "request", "command": command, "arguments": arguments or {}})
    proc.stdin.write(f"Content-Length: {len(body)}\r\n\r\n{body}".encode())
    proc.stdin.flush()
    while True:
        length = 0
        while line := proc.stdout.readline().strip():
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":")[1])
        message = json.loads(proc.stdout.read(length))
        if message.get("event") == "stopped":
            print(f"stopped: {message['body'].get('reason')}")
        if message.get("type") == "response" and message.get("request_seq") == seq:
            if not message.get("success"):
                sys.exit(f"{command} failed: {message.get('message')}")
            return message.get("body") or {}


def stack():
    for frame in send("stackTrace", {"threadId": 1})["stackFrames"]:
        source = frame.get("source") or {}
        print(f"frame: {frame['name']} {source.get('name', '?')}:{frame['line']}")


send("initialize", {"adapterID": "soldb"})
send("launch", {"traceFile": trace, "contracts": contracts})
stack()
args = iter(commands)
for command in args:
    if command == "break":
        path, line = next(args).rsplit(":", 1)
        body = send("setBreakpoints", {"source": {"path": path}, "breakpoints": [{"line": int(line)}]})
        print(f"breakpoint: {path}:{line} verified={body['breakpoints'][0]['verified']}")
        continue
    send(command, {"threadId": 1})
    stack()
send("disconnect")
proc.wait()
