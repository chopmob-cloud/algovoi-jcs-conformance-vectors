// KAF network canary (real program file, never run via jshell/eval).
// Exit 0 iff the network is UNREACHABLE (hermetic). Exit 1 otherwise.
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;

public class NetCanary {
    public static void main(String[] args) {
        List<String> reachable = new ArrayList<>();

        String[][] probes = { {"1.1.1.1", "443"}, {"8.8.8.8", "53"} };
        for (String[] probe : probes) {
            String host = probe[0];
            int port = Integer.parseInt(probe[1]);
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(host, port), 2000);
                reachable.add("tcp " + host + ":" + port);
            } catch (SocketTimeoutException e) {
                // A timeout is INCONCLUSIVE (e.g. a firewall drop on an otherwise-open
                // network), not proof of isolation. Fail closed: count as reachable so a
                // drop-based environment cannot false-pass the hermeticity proof.
                reachable.add("tcp " + host + ":" + port + " (timeout: inconclusive, fail-closed)");
            } catch (Exception e) {
                // Genuine no route (ConnectException / NoRouteToHostException): isolated.
            }
        }

        // DNS resolution probe; a successful lookup to a valid IP means resolvers are reachable.
        try {
            InetAddress resolved = InetAddress.getByName("one.one.one.one");
            if (resolved != null) {
                reachable.add("dns one.one.one.one");
            }
        } catch (Exception e) {
            // unreachable is the desired state
        }

        if (!reachable.isEmpty()) {
            System.out.println("NETWORK=REACHABLE " + String.join("; ", reachable));
            System.exit(1);
        }
        System.out.println("NETWORK=NONE (all probes failed, hermetic)");
        System.exit(0);
    }
}
