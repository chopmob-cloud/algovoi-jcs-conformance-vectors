# Keystone L3 gauntlet -- guard_context, Elixir (jcs 0.2.0 hex).
Mix.install([{:jcs, "~> 0.2.0"}, {:jason, "~> 1.4"}])
defmodule G do
  @ref ~r/^sha256:[0-9a-f]{64}$/
  defp is_ref(v), do: is_binary(v) and Regex.match?(@ref, v)
  defp href(obj), do: "sha256:" <> (:crypto.hash(:sha256, :erlang.iolist_to_binary(Jcs.encode(obj))) |> Base.encode16(case: :lower))
  def gcr(ts, pr, mr, pcr) do
    unless is_integer(ts) and ts >= 0, do: throw(:bad)
    for v <- [pr, mr, pcr], do: (unless is_ref(v), do: throw(:bad))
    href(%{"canon_version" => "jcs-rfc8785-v1", "type" => "guard_context", "guard_timestamp_ms" => ts,
           "policy_ref" => pr, "mandate_ref" => mr, "passport_credential_ref" => pcr})
  end
  def safe(fun), do: (try do {:ok, fun.()} catch :throw, _ -> :err; _, _ -> :err end)
  def run(path) do
    d = File.read!(path) |> Jason.decode!()
    {ok, fails} = Enum.reduce(d["vectors"], {0, []}, fn v, {ok, fails} ->
      case safe(fn -> gcr(v["guard_timestamp_ms"], v["policy_ref"], v["mandate_ref"], v["passport_credential_ref"]) end) do
        {:ok, r} -> if r == v["expected_guard_context_ref"], do: {ok + 1, fails}, else: {ok, [v["id"] | fails]}
        :err -> {ok, [v["id"] | fails]}
      end
    end)
    {ok, fails} = Enum.reduce(d["negatives"], {ok, fails}, fn n, {ok, fails} ->
      if n["must"] == "reject" do
        case safe(fn -> gcr(n["guard_timestamp_ms"], n["policy_ref"], n["mandate_ref"], n["passport_credential_ref"]) end) do :err -> {ok + 1, fails}; _ -> {ok, [n["id"] | fails]} end
      else
        case safe(fn -> gcr(n["guard_timestamp_ms"], n["policy_ref"], n["mandate_ref"], n["passport_credential_ref"]) end) do
          {:ok, r} -> if r != n["claimed_guard_context_ref"], do: {ok + 1, fails}, else: {ok, [n["id"] | fails]}
          :err -> {ok, [n["id"] | fails]}
        end
      end
    end)
    v0 = hd(d["vectors"])
    a = gcr(v0["guard_timestamp_ms"], v0["policy_ref"], v0["mandate_ref"], v0["passport_credential_ref"])
    b = gcr(v0["guard_timestamp_ms"] + 1, v0["policy_ref"], v0["mandate_ref"], v0["passport_credential_ref"])
    {ok, fails} = if a != b, do: {ok + 1, fails}, else: {ok, ["moment" | fails]}
    {ok, fails} = case safe(fn -> gcr(1720000000000.5, v0["policy_ref"], v0["mandate_ref"], v0["passport_credential_ref"]) end) do :err -> {ok + 1, fails}; _ -> {ok, ["float" | fails]} end
    total = length(d["vectors"]) + length(d["negatives"]) + 2
    Enum.each(Enum.reverse(fails), fn f -> IO.puts("  FAIL #{f}") end)
    IO.puts("KEYSTONE-GAUNTLET-GC elixir #{ok}/#{total}")
    if ok == total and fails == [], do: System.halt(0), else: System.halt(1)
  end
end
[path] = System.argv()
G.run(path)
