#!/usr/bin/env bash
# run_all.sh -- run every rfc9421_proxy_chain_v1 runner and tally PASS/FAIL.
# Conformant set: all runners verify the RFC 9421 §2.5 signing base.
#
# Pre-requisites (installed once on the host):
#   pip install algovoi-rfc9421-verifier ; npm install ; gem install ed25519
#   (Go, Rust, Java JDK 17+, PHP 8 with ext-sodium, .NET 8+ on PATH)
set -u
cd "$(dirname "$0")"

PASS=0; FAIL=0; FAILED=()
run() { local name="$1"; shift; echo; echo "=== $name ==="; if "$@"; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); FAILED+=("$name"); fi; }

run "Python (algovoi-rfc9421-verifier, mode=rfc9421)" python runner_python.py
run "Node (inline + node:crypto)"                     node runner_node.js
run "Go (stdlib crypto/ed25519)"                      go run runner_go.go
run "Rust (ed25519-dalek)"                            bash -c 'cd runner_rust && cargo run --release --quiet'
run "Java (JDK 17 stdlib Ed25519)"                    java runner_java.java
run "PHP (libsodium)"                                 php runner_php.php
run ".NET (NSec.Cryptography)"                         bash -c 'cd runner_dotnet && dotnet run -c Release --verbosity quiet'
run "Ruby (ed25519 gem)"                              ruby runner_ruby.rb

echo; echo "=============================="; echo "Summary: $PASS PASS / $FAIL FAIL"
if [ "$FAIL" -gt 0 ]; then echo "Failed:"; for n in "${FAILED[@]}"; do echo "  - $n"; done; exit 1; fi
echo "8/8 PASS"; exit 0
