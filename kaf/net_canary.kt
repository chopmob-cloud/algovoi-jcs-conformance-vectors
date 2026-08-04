// KAF network canary (real program file, never run via -e/eval).
// Exit 0 iff the network is UNREACHABLE (hermetic). Exit 1 otherwise.
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import kotlin.system.exitProcess

fun main() {
    val reachable = mutableListOf<String>()

    val probes = listOf("1.1.1.1" to 443, "8.8.8.8" to 53)
    for ((host, port) in probes) {
        try {
            Socket().use { s ->
                s.connect(InetSocketAddress(host, port), 2000)
            }
            reachable.add("tcp $host:$port")
        } catch (e: SocketTimeoutException) {
            // A timeout is INCONCLUSIVE (e.g. a firewall drop on an otherwise-open
            // network), not proof of isolation. Fail closed: count as reachable so a
            // drop-based environment cannot false-pass the hermeticity proof.
            reachable.add("tcp $host:$port (timeout: inconclusive, fail-closed)")
        } catch (e: Exception) {
            // Genuine no route (ConnectException / NoRouteToHostException): isolated.
        }
    }

    // DNS resolution probe; a successful lookup to a valid IP means resolvers are reachable.
    try {
        val resolved = InetAddress.getByName("one.one.one.one")
        if (resolved != null) {
            reachable.add("dns one.one.one.one")
        }
    } catch (e: Exception) {
        // unreachable is the desired state
    }

    if (reachable.isNotEmpty()) {
        println("NETWORK=REACHABLE " + reachable.joinToString("; "))
        exitProcess(1)
    }
    println("NETWORK=NONE (all probes failed, hermetic)")
    exitProcess(0)
}
