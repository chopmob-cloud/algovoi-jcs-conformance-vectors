// KAF network canary (real program file, never run via csi/eval).
// Exit 0 iff the network is UNREACHABLE (hermetic). Exit 1 otherwise.
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

class NetCanary
{
    static int Main()
    {
        var reachable = new List<string>();

        var probes = new (string host, int port)[] { ("1.1.1.1", 443), ("8.8.8.8", 53) };
        foreach (var (host, port) in probes)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(host, port);
                // 2-second connect timeout. Task.WaitAny returns the index of the
                // completed task, or -1 if the timeout elapsed first.
                bool completed = connectTask.Wait(2000);
                if (completed && client.Connected)
                {
                    reachable.Add($"tcp {host}:{port}");
                }
                else if (!completed)
                {
                    // A timeout is INCONCLUSIVE (e.g. a firewall drop on an otherwise-open
                    // network), not proof of isolation. Fail closed: count as reachable so a
                    // drop-based environment cannot false-pass the hermeticity proof.
                    reachable.Add($"tcp {host}:{port} (timeout: inconclusive, fail-closed)");
                }
                // else: connect task completed but not connected => treated below by catch/no-op
            }
            catch (AggregateException ae) when (HasSocketTimeout(ae))
            {
                // Some platforms surface a connect timeout as a SocketException with a
                // TimedOut error code wrapped in the awaited task. Fail closed.
                reachable.Add($"tcp {host}:{port} (timeout: inconclusive, fail-closed)");
            }
            catch (Exception)
            {
                // Genuine no route (ConnectionRefused / NetworkUnreachable / HostUnreachable):
                // isolated. Do nothing.
            }
        }

        // DNS resolution probe; a successful lookup to a valid IP means resolvers are reachable.
        try
        {
            IPHostEntry entry = Dns.GetHostEntry("one.one.one.one");
            if (entry != null && entry.AddressList != null && entry.AddressList.Length > 0)
            {
                reachable.Add("dns one.one.one.one");
            }
        }
        catch (Exception)
        {
            // unreachable is the desired state
        }

        if (reachable.Count > 0)
        {
            Console.WriteLine("NETWORK=REACHABLE " + string.Join("; ", reachable));
            return 1;
        }
        Console.WriteLine("NETWORK=NONE (all probes failed, hermetic)");
        return 0;
    }

    static bool HasSocketTimeout(AggregateException ae)
    {
        foreach (var e in ae.Flatten().InnerExceptions)
        {
            if (e is SocketException se && se.SocketErrorCode == SocketError.TimedOut)
            {
                return true;
            }
        }
        return false;
    }
}
