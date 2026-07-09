#!/usr/bin/env elixir
# Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE in this directory.
# Retention Chain v1 vector runner -- Elixir / jcs 0.2.0 (pzingg/jcs, hex.pm)
#
# Usage: elixir runner_elixir.exs <vector_set_json>
# Requires: Elixir 1.14+ / OTP 25+ (Mix.install fetches jcs + jason on first run;
# needs network access once, then caches under ~/.mix or MIX_INSTALL_DIR)

Mix.install([
  {:jcs, "~> 0.2.0"},
  {:jason, "~> 1.4"}
])

defmodule Runner do
  def sha256_jcs(term) do
    canon = Jcs.encode(term)
    bytes = :erlang.iolist_to_binary(canon)
    b64 = Base.encode64(bytes)
    ref = "sha256:" <> (:crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower))
    {b64, ref}
  end

  def run(path) do
    data = File.read!(path) |> Jason.decode!()

    {pass, fail} =
      Enum.reduce(data["vectors"], {0, 0}, fn v, {pass, fail} ->
        {b64, ref} = sha256_jcs(v["preimage"])
        b64_ok = b64 == v["expected_jcs_bytes_b64"]
        ref_ok = ref == v["expected_chain_ref"]

        unless b64_ok, do: IO.puts("  FAIL #{v["vector_id"]} jcs_bytes_b64 mismatch")
        unless ref_ok, do: IO.puts("  FAIL #{v["vector_id"]} chain_ref (got #{ref})")

        if b64_ok && ref_ok, do: {pass + 1, fail}, else: {pass, fail + 1}
      end)

    IO.puts("#{pass}/#{pass + fail} PASS")
    System.halt(if fail == 0, do: 0, else: 1)
  end
end

[path] = System.argv()
Runner.run(path)
