#!/usr/bin/env bash
# run_all.sh -- run every retention_chain_v1 runner and tally PASS/FAIL.
# All runners validate sha256(JCS(preimage)) == expected_chain_ref for 14 vectors.
#
# Pre-requisites (installed once on the host):
#   pip install rfc8785 ; npm install ; gem install json-canonicalization
#   (Go, PHP 8 with ext-sodium, Java JDK 17+, .NET 9+, Rust on PATH)
set -u
cd "$(dirname "$0")"

PASS=0; FAIL=0; FAILED=()
run() { local name="$1"; shift; echo; echo "=== $name ==="; if "$@"; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); FAILED+=("$name"); fi; }

run "Python (rfc8785@0.1.4)"                         python runner_python.py retention_chain_v1.json
run "Node (canonicalize@1.0.8)"                       node runner_node.js retention_chain_v1.json
run "Go (gowebpki/jcs v1.0.1)"                        go run runner_go.go retention_chain_v1.json
run "Ruby (json-canonicalization 1.0.0)"              ruby runner_ruby.rb retention_chain_v1.json
run "PHP (inline RFC 8785 + libsodium)"               php runner_php.php retention_chain_v1.json
run "Java (java-json-canonicalization 1.1)"           bash -c 'cd runner_java && java -cp ".:libs/*" Runner.java ../retention_chain_v1.json'
run ".NET 9 (Baqhub.Packages.JsonCanonicalization)"   bash -c 'cd runner_dotnet && dotnet run -c Release --verbosity quiet -- ../retention_chain_v1.json'
run "Rust (serde_jcs + sha2)"                         bash -c 'cd runner_rust && cargo run --release --quiet -- ../retention_chain_v1.json'

echo; echo "=============================="; echo "Summary: $PASS PASS / $FAIL FAIL"
if [ "$FAIL" -gt 0 ]; then echo "Failed:"; for n in "${FAILED[@]}"; do echo "  - $n"; done; exit 1; fi
echo "8/8 PASS"; exit 0
