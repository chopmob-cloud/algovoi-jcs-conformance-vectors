#!/usr/bin/env bash
# Claim 1 (input bytes) 8-language byte-for-byte cross-validation — adversarial_isolation_v1.
# Each runner prints "12/12 PASS" (8 x 12 = 96/96). Claim 2 (rejection PoR) is the reference
# implementation only — run `python ../../vectors/adversarial_isolation_v1/runner_python.py`
# for the combined Claim 1 + Claim 2 check.
set -u
V="$(dirname "$0")/../../vectors/adversarial_isolation_v1/adversarial_isolation_v1.json"
cd "$(dirname "$0")"
echo -n "Python  "; python runner_python.py "$V"
echo -n "Node    "; node runner_node.js "$V"
echo -n "Ruby    "; ruby runner_ruby.rb "$V"
echo -n "PHP     "; php runner_php.php "$V"
echo -n "Go      "; go run runner_go.go "$V"
echo -n "Rust    "; ( cd runner_rust && cargo +stable-x86_64-pc-windows-gnu run --release --quiet -- "$V" )
echo -n "Java    "; ( cd runner_java && javac -cp "libs/*" Runner.java && java -cp ".;libs/*" Runner "$V" )
echo -n ".NET    "; ( cd runner_dotnet && dotnet run -c Release --verbosity quiet -- "$V" )
echo "Expected: 12/12 PASS x 8 languages = 96/96 byte-for-byte (Claim 1)."
