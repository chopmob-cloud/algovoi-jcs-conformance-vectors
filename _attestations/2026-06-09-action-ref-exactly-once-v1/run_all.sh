#!/usr/bin/env bash
# 8-language byte-for-byte cross-validation — action_ref_exactly_once_v1.
# Each runner prints "6/6 PASS". Requires Python 3.12, Node 24, Ruby 3.4, PHP 8.4,
# Go 1.26, Rust 1.95 (gnu toolchain), Java 17, .NET 9 on PATH, plus algovoi-substrate
# (Python) and canonicalize (npm) — the latter vendored in node_modules/.
set -u
V="$(dirname "$0")/../../vectors/action_ref_exactly_once_v1/action_ref_exactly_once_v1.json"
cd "$(dirname "$0")"
echo -n "Python  "; python runner_python.py "$V"
echo -n "Node    "; node runner_node.js "$V"
echo -n "Ruby    "; ruby runner_ruby.rb "$V"
echo -n "PHP     "; php runner_php.php "$V"
echo -n "Go      "; go run runner_go.go "$V"
echo -n "Rust    "; ( cd runner_rust && cargo +stable-x86_64-pc-windows-gnu run --release --quiet -- "$V" )
echo -n "Java    "; ( cd runner_java && javac -cp "libs/*" Runner.java && java -cp ".;libs/*" Runner "$V" )
echo -n ".NET    "; ( cd runner_dotnet && dotnet run -c Release --verbosity quiet -- "$V" )
echo "Expected: 6/6 PASS x 8 languages = 48/48 byte-for-byte."
