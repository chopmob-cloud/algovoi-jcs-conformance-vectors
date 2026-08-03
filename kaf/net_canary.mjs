// KAF network canary (real module file, never run via -e/eval: eval contexts
// inject globals that mask environment defects, the Node 18 lesson).
// Exit 0 iff the network is UNREACHABLE (hermetic). Exit 1 otherwise.
import net from "node:net";
import dns from "node:dns/promises";

const reachable = [];

function probe(host, port) {
  return new Promise((resolve) => {
    const sock = net.connect({ host, port, timeout: 2000 });
    sock.on("connect", () => { sock.destroy(); resolve(`tcp ${host}:${port}`); });
    // A timeout is INCONCLUSIVE (e.g. a firewall drop on an otherwise-open
    // network), not proof of isolation: fail closed by counting it as reachable.
    sock.on("timeout", () => { sock.destroy(); resolve(`tcp ${host}:${port} (timeout: inconclusive, fail-closed)`); });
    // A genuine error (ECONNREFUSED/ENETUNREACH) IS isolation.
    sock.on("error", () => resolve(null));
  });
}

for (const [h, p] of [["1.1.1.1", 443], ["8.8.8.8", 53]]) {
  const r = await probe(h, p);
  if (r) reachable.push(r);
}
try {
  await dns.lookup("one.one.one.one");
  reachable.push("dns one.one.one.one");
} catch { /* unreachable is the desired state */ }

if (reachable.length > 0) {
  console.log("NETWORK=REACHABLE " + reachable.join("; "));
  process.exit(1);
}
console.log("NETWORK=NONE (all probes failed, hermetic)");
process.exit(0);
