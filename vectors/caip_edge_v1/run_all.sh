#!/bin/bash
# Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0.
# Run the two correct references (must agree, 102/102) and the two naive trap demonstrators.
set -e
cd "$(dirname "$0")"
echo "== Python reference (\\A..\\Z) =="
python runner_python.py
echo
echo "== Node reference (^..\$ no m) =="
node runner_node.mjs
echo
echo "== Python NAIVE (^...\$) -- trailing-newline trap =="
python runner_python_naive.py
echo
echo "== Node NAIVE (^..\$ WITH m) -- line-terminator + newline-injection trap =="
node runner_node_naive.mjs
