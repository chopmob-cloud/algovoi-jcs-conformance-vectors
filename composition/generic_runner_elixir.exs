#!/usr/bin/env elixir
# Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE in this directory.
# Generic JCS hash-comparison runner -- Elixir / jcs 0.2.0 (pzingg/jcs, hex.pm)
#
# Validates sha256(JCS(vector[payload_field])) == vector[hash_field] (optionally
# "sha256:"-prefixed) for every vector in a set's JSON file. payload_field and
# hash_field may each be a comma-separated fallback list (e.g. "receipt,row") --
# the first key actually present on the vector is used, matching this corpus's
# own reference runners where different vector kinds (e.g. receipts vs. audit
# chain rows) use different field names within the same set.
#
# Usage: elixir generic_runner_elixir.exs <json_path> <payload_fields> <hash_fields> <prefix:0|1> [b64_fields]

Mix.install([{:jcs, "~> 0.2.0"}, {:jason, "~> 1.4"}])

[path, payload_fields, hash_fields, prefix_flag | rest] = System.argv()
b64_fields = List.first(rest)
prefix = if prefix_flag == "1", do: "sha256:", else: ""

split = fn s -> if s, do: String.split(s, ","), else: [] end
first_present = fn v, fields -> Enum.find_value(fields, fn f -> if Map.has_key?(v, f), do: {f, v[f]} end) end

data = File.read!(path) |> Jason.decode!()

{pass, fail} =
  Enum.reduce(data["vectors"], {0, 0}, fn v, {pass, fail} ->
    vid = v["vector_id"] || v["id"]
    {_, payload} = first_present.(v, split.(payload_fields))
    {hfield, hexp} = first_present.(v, split.(hash_fields))

    canon = Jcs.encode(payload)
    bytes = :erlang.iolist_to_binary(canon)
    b64 = Base.encode64(bytes)
    ref = prefix <> (:crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower))

    hash_ok = ref == hexp

    b64_ok =
      case first_present.(v, split.(b64_fields)) do
        nil -> true
        {_, b64exp} -> b64 == b64exp
      end

    unless hash_ok, do: IO.puts("  FAIL #{vid} #{hfield} mismatch (got #{ref}, expected #{hexp})")
    unless b64_ok, do: IO.puts("  FAIL #{vid} jcs_bytes_b64 mismatch")

    if hash_ok && b64_ok, do: {pass + 1, fail}, else: {pass, fail + 1}
  end)

IO.puts("#{pass}/#{pass + fail} PASS")
System.halt(if fail == 0, do: 0, else: 1)
