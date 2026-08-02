#!/usr/bin/env python3
"""KAF network canary (real module file, never run via -c/eval).

Exit 0 iff the network is UNREACHABLE, which is what a hermetic execution
cell requires. Exit 1 if any probe connects or resolves.
"""
import socket
import sys

reachable = []

for host, port in (("1.1.1.1", 443), ("8.8.8.8", 53)):
    try:
        s = socket.create_connection((host, port), timeout=2)
        s.close()
        reachable.append(f"tcp {host}:{port}")
    except OSError:
        pass

try:
    socket.getaddrinfo("one.one.one.one", 443)
    reachable.append("dns one.one.one.one")
except OSError:
    pass

if reachable:
    print("NETWORK=REACHABLE " + "; ".join(reachable))
    sys.exit(1)
print("NETWORK=NONE (all probes failed, hermetic)")
sys.exit(0)
