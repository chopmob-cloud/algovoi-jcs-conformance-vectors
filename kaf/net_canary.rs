// KAF network canary (real program file, never run via -e/eval).
// Exit 0 iff the network is UNREACHABLE (hermetic). Exit 1 otherwise.
// std only, no external crates; compilable directly with `rustc net_canary.rs`.
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::exit;
use std::time::Duration;

fn main() {
    let mut reachable: Vec<String> = Vec::new();

    for (host, port) in [("1.1.1.1", 443u16), ("8.8.8.8", 53u16)] {
        // Parse the literal IP:port into a SocketAddr (no DNS involved here).
        let addr: SocketAddr = format!("{host}:{port}")
            .parse()
            .expect("literal address must parse");
        match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
            Ok(_stream) => {
                reachable.push(format!("tcp {host}:{port}"));
            }
            Err(e) if e.kind() == ErrorKind::TimedOut => {
                // A timeout is INCONCLUSIVE (e.g. a firewall drop on an otherwise-open
                // network), not proof of isolation. Fail closed: count as reachable so a
                // drop-based environment cannot false-pass the hermeticity proof.
                reachable.push(format!("tcp {host}:{port} (timeout: inconclusive, fail-closed)"));
            }
            Err(_) => {
                // Genuine no route (ECONNREFUSED / ENETUNREACH / EHOSTUNREACH): isolated.
            }
        }
    }

    // DNS resolution probe via ToSocketAddrs; a successful resolve to any address
    // means resolvers are reachable.
    if let Ok(mut iter) = ("one.one.one.one", 443u16).to_socket_addrs() {
        if iter.next().is_some() {
            reachable.push("dns one.one.one.one".to_string());
        }
    }

    if !reachable.is_empty() {
        println!("NETWORK=REACHABLE {}", reachable.join("; "));
        exit(1);
    }
    println!("NETWORK=NONE (all probes failed, hermetic)");
    exit(0);
}
