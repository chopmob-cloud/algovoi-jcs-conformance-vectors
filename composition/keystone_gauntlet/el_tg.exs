# trust_gate deny-table gauntlet -- Elixir.
Mix.install([{:jason, "~> 1.4"}])
defmodule G do
  @deny %{"block_untrusted" => ["UNTRUSTED"], "require_trusted" => ["UNTRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE"]}
  def blocks(mode, verdict) do
    cond do
      is_nil(mode) or not is_binary(mode) or mode == "off" -> false
      true -> verdict in Map.get(@deny, mode, [])
    end
  end
  def run(path) do
    d = File.read!(path) |> Jason.decode!()
    {ok, fails} = Enum.reduce(d["vectors"], {0, []}, fn v, {ok, fails} ->
      if blocks(v["mode"], v["verdict"]) == v["expected_blocks"], do: {ok + 1, fails}, else: {ok, [v["id"] | fails]}
    end)
    total = length(d["vectors"])
    Enum.each(Enum.reverse(fails), fn f -> IO.puts("  FAIL #{f}") end)
    IO.puts("TRUST-GATE-GAUNTLET elixir #{ok}/#{total}")
    if ok == total and fails == [], do: System.halt(0), else: System.halt(1)
  end
end
[path] = System.argv()
G.run(path)
