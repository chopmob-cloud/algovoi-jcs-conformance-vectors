# revocation_ref fail-closed gauntlet -- Elixir (jcs 0.2.0 hex).
Mix.install([{:jcs, "~> 0.2.0"}, {:jason, "~> 1.4"}])
defmodule G do
  @ref ~r/^sha256:[0-9a-f]{64}$/
  @reasons ["USER_REQUESTED", "COMPLIANCE_TRIGGERED", "EXPIRED", "KEY_COMPROMISE", "SUPERSEDED", "ADMIN"]
  @status ["active", "suspended", "revoked", "inactive"]
  defp is_ref(v), do: is_binary(v) and Regex.match?(@ref, v)
  defp hjcs(obj), do: "sha256:" <> (:crypto.hash(:sha256, :erlang.iolist_to_binary(Jcs.encode(obj))) |> Base.encode16(case: :lower))
  def rref(f) do
    unless is_ref(f["subject_ref"]), do: throw(:bad)
    ms = f["revoked_at_ms"]; unless is_integer(ms) and ms >= 0, do: throw(:bad)
    rc = f["reason_code"]; unless rc in @reasons, do: throw(:bad)
    did = f["issuer_did"]; unless is_binary(did) and did != "", do: throw(:bad)
    ps = f["prev_status"]; unless ps in @status, do: throw(:bad)
    ns = f["new_status"]; unless ns in @status, do: throw(:bad)
    sq = f["seq"]; unless is_integer(sq) and sq >= 0, do: throw(:bad)
    prev = cond do
      is_nil(f["prev_revocation_ref"]) -> nil
      is_ref(f["prev_revocation_ref"]) -> f["prev_revocation_ref"]
      true -> throw(:bad)
    end
    hjcs(%{"canon_version" => "jcs-rfc8785-v1", "type" => "revocation_link", "subject_ref" => f["subject_ref"],
           "revoked_at_ms" => ms, "reason_code" => rc, "issuer_did" => did, "prev_status" => ps,
           "new_status" => ns, "seq" => sq, "prev_revocation_ref" => prev})
  end
  def safe(fun), do: (try do {:ok, fun.()} catch :throw, _ -> :err; _, _ -> :err end)
  def vchain(links), do: vchain(links, 0, nil)
  defp vchain([], _i, _prev), do: true
  defp vchain([l | rest], i, prev) do
    cond do
      l["seq"] != i -> false
      Map.get(l, "prev_revocation_ref") != prev -> false
      true -> vchain(rest, i + 1, hjcs(l))
    end
  end
  def run(path) do
    d = File.read!(path) |> Jason.decode!()
    {ok, fails} = Enum.reduce(d["vectors"], {0, []}, fn v, {ok, fails} ->
      case safe(fn -> rref(v) end) do
        {:ok, r} -> if r == v["expected_revocation_ref"], do: {ok + 1, fails}, else: {ok, [v["id"] | fails]}
        :err -> {ok, [v["id"] | fails]}
      end
    end)
    {ok, fails} = Enum.reduce(d["negatives"], {ok, fails}, fn n, {ok, fails} ->
      case safe(fn -> rref(n) end) do :err -> {ok + 1, fails}; _ -> {ok, [n["id"] | fails]} end
    end)
    {ok, fails} = Enum.reduce(d["tamper"], {ok, fails}, fn t, {ok, fails} ->
      case safe(fn -> rref(t) end) do
        {:ok, r} -> if r != t["claimed_revocation_ref"], do: {ok + 1, fails}, else: {ok, [t["id"] | fails]}
        :err -> {ok, [t["id"] | fails]}
      end
    end)
    {ok, fails} = Enum.reduce(d["chain_valid"], {ok, fails}, fn c, {ok, fails} ->
      if vchain(c["links"]), do: {ok + 1, fails}, else: {ok, [c["id"] | fails]}
    end)
    {ok, fails} = Enum.reduce(d["chain_invalid"], {ok, fails}, fn c, {ok, fails} ->
      if not vchain(c["links"]), do: {ok + 1, fails}, else: {ok, [c["id"] | fails]}
    end)
    total = length(d["vectors"]) + length(d["negatives"]) + length(d["tamper"]) + length(d["chain_valid"]) + length(d["chain_invalid"])
    Enum.each(Enum.reverse(fails), fn f -> IO.puts("  FAIL #{f}") end)
    IO.puts("REVOCATION-GAUNTLET elixir #{ok}/#{total}")
    if ok == total and fails == [], do: System.halt(0), else: System.halt(1)
  end
end
[path] = System.argv()
G.run(path)
