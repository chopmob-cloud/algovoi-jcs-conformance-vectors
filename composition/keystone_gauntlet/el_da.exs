# Keystone L3 gauntlet -- decision_audit, Elixir (jcs 0.2.0 hex).
Mix.install([{:jcs, "~> 0.2.0"}, {:jason, "~> 1.4"}])
defmodule G do
  @ref ~r/^sha256:[0-9a-f]{64}$/
  defp is_ref(v), do: is_binary(v) and Regex.match?(@ref, v)
  defp href(obj), do: "sha256:" <> (:crypto.hash(:sha256, :erlang.iolist_to_binary(Jcs.encode(obj))) |> Base.encode16(case: :lower))
  def dar(f, with_screen) do
    for k <- ["decision_ref", "passport_credential_ref", "mandate_ref", "policy_bound_ref"] do
      unless is_ref(f[k]), do: throw(:bad)
    end
    obj = %{"decision_ref" => f["decision_ref"], "passport_credential_ref" => f["passport_credential_ref"],
            "mandate_ref" => f["mandate_ref"], "policy_bound_ref" => f["policy_bound_ref"]}
    obj = if with_screen do
      case f["screen_binding_ref"] do
        nil -> obj
        sbr -> (unless is_ref(sbr), do: throw(:bad)); Map.put(obj, "screen_binding_ref", sbr)
      end
    else obj end
    href(obj)
  end
  def safe(fun), do: (try do {:ok, fun.()} catch :throw, _ -> :err; _, _ -> :err end)
  def run(path) do
    d = File.read!(path) |> Jason.decode!()
    {ok, fails} = Enum.reduce(d["vectors"], {0, []}, fn v, {ok, fails} ->
      case safe(fn -> dar(v, true) end) do
        {:ok, r} -> if r == v["expected_decision_audit_ref"], do: {ok + 1, fails}, else: {ok, [v["id"] | fails]}
        :err -> {ok, [v["id"] | fails]}
      end
    end)
    {ok, fails} = Enum.reduce(d["negatives"], {ok, fails}, fn n, {ok, fails} ->
      if n["must"] == "reject" do
        case safe(fn -> dar(n, true) end) do :err -> {ok + 1, fails}; _ -> {ok, [n["id"] | fails]} end
      else
        case safe(fn -> dar(n, true) end) do
          {:ok, r} -> if r != n["claimed_decision_audit_ref"], do: {ok + 1, fails}, else: {ok, [n["id"] | fails]}
          :err -> {ok, [n["id"] | fails]}
        end
      end
    end)
    v0 = hd(d["vectors"])
    {ok, fails} = if dar(v0, true) != dar(v0, false), do: {ok + 1, fails}, else: {ok, ["screen" | fails]}
    {ok, fails} = case safe(fn -> dar(Map.put(v0, "decision_ref", "bad"), true) end) do :err -> {ok + 1, fails}; _ -> {ok, ["malformed" | fails]} end
    total = length(d["vectors"]) + length(d["negatives"]) + 2
    Enum.each(Enum.reverse(fails), fn f -> IO.puts("  FAIL #{f}") end)
    IO.puts("KEYSTONE-GAUNTLET elixir #{ok}/#{total}")
    if ok == total and fails == [], do: System.halt(0), else: System.halt(1)
  end
end
[path] = System.argv()
G.run(path)
