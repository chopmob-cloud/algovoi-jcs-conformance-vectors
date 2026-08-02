# Differential adversarial substrate -- Elixir canon probe (jcs 0.2.0 hex).
# Contract: see probe_python.py. Emits "<id>\t h:<hex> | R:<reason>" per case.
Mix.install([{:jcs, "~> 0.2.0"}, {:jason, "~> 1.4"}])

defmodule P do
  def v(raw) do
    case Jason.decode(raw) do
      {:ok, val} ->
        try do
          canon = :erlang.iolist_to_binary(Jcs.encode(val))
          "h:" <> (:crypto.hash(:sha256, canon) |> Base.encode16(case: :lower))
        rescue
          _ -> "R:canon"
        catch
          _, _ -> "R:canon"
        end

      _ ->
        "R:parse"
    end
  end

  def run(path) do
    d = File.read!(path) |> Jason.decode!()
    lines = Enum.map(d["cases"], fn c -> "#{c["id"]}\t#{v(c["raw"])}" end)
    IO.puts(Enum.join(lines, "\n"))
  end
end

[path] = System.argv()
P.run(path)
