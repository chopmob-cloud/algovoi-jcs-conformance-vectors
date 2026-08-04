# KAF network canary (real script file, never run via elixir -e/eval).
# Exit 0 iff the network is UNREACHABLE (hermetic). Exit 1 otherwise.

reachable =
  Enum.reduce([{~c"1.1.1.1", 443}, {~c"8.8.8.8", 53}], [], fn {host, port}, acc ->
    case :gen_tcp.connect(host, port, [:binary, active: false], 2000) do
      {:ok, socket} ->
        :gen_tcp.close(socket)
        acc ++ ["tcp #{host}:#{port}"]

      {:error, :timeout} ->
        # A timeout is INCONCLUSIVE (e.g. a firewall drop on an otherwise-open
        # network), not proof of isolation. Fail closed: count as reachable so a
        # drop-based environment cannot false-pass the hermeticity proof.
        acc ++ ["tcp #{host}:#{port} (timeout: inconclusive, fail-closed)"]

      {:error, _reason} ->
        # Genuine no route (econnrefused / enetunreach / ehostunreach): isolated.
        acc
    end
  end)

# DNS resolution probe; a successful lookup to a valid IP means resolvers are reachable.
reachable =
  case :inet.gethostbyname(~c"one.one.one.one") do
    {:ok, _hostent} -> reachable ++ ["dns one.one.one.one"]
    {:error, _reason} -> reachable
  end

if reachable != [] do
  IO.puts("NETWORK=REACHABLE " <> Enum.join(reachable, "; "))
  System.halt(1)
else
  IO.puts("NETWORK=NONE (all probes failed, hermetic)")
  System.halt(0)
end
