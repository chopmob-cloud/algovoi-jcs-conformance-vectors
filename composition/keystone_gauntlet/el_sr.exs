# settlement_round validity gauntlet -- Elixir.
Mix.install([{:jason, "~> 1.4"}])
defmodule G do
  def rpi_ok(v), do: is_integer(v) and not is_boolean(v) and v > 0
  def run(path) do
    d = File.read!(path) |> Jason.decode!()
    {ok, fails} = Enum.reduce(d["settlement_round_reject_vectors"], {0, []}, fn r, {ok, fails} ->
      if not rpi_ok(get_in(r, ["receipt", "settlement_round"])), do: {ok + 1, fails}, else: {ok, [r["vector_id"] | fails]}
    end)
    acc = Enum.find(d["vectors"], fn v -> is_integer(get_in(v, ["receipt", "settlement_round"])) end)
    {ok, fails} = if rpi_ok(get_in(acc, ["receipt", "settlement_round"])), do: {ok + 1, fails}, else: {ok, [acc["vector_id"] | fails]}
    total = length(d["settlement_round_reject_vectors"]) + 1
    Enum.each(Enum.reverse(fails), fn f -> IO.puts("  FAIL #{f}") end)
    IO.puts("SETTLEMENT-ROUND-GAUNTLET elixir #{ok}/#{total}")
    if ok == total and fails == [], do: System.halt(0), else: System.halt(1)
  end
end
[path] = System.argv()
G.run(path)
