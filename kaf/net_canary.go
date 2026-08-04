// KAF network canary (real program file, never run via -e/eval).
// Exit 0 iff the network is UNREACHABLE (hermetic). Exit 1 otherwise.
package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	var reachable []string

	probes := []struct {
		host string
		port string
	}{
		{"1.1.1.1", "443"},
		{"8.8.8.8", "53"},
	}

	for _, p := range probes {
		addr := net.JoinHostPort(p.host, p.port)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			reachable = append(reachable, fmt.Sprintf("tcp %s:%s", p.host, p.port))
			continue
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			// A timeout is INCONCLUSIVE (e.g. a firewall drop on an otherwise-open
			// network), not proof of isolation. Fail closed: count as reachable so a
			// drop-based environment cannot false-pass the hermeticity proof.
			reachable = append(reachable, fmt.Sprintf("tcp %s:%s (timeout: inconclusive, fail-closed)", p.host, p.port))
			continue
		}
		// Genuine no route (ECONNREFUSED / ENETUNREACH / EHOSTUNREACH): isolated.
	}

	// DNS resolution probe: a successful lookup to a valid IP means resolvers are reachable.
	if addrs, err := net.LookupHost("one.one.one.one"); err == nil && len(addrs) > 0 {
		reachable = append(reachable, "dns one.one.one.one")
	}

	if len(reachable) > 0 {
		fmt.Println("NETWORK=REACHABLE " + strings.Join(reachable, "; "))
		os.Exit(1)
	}
	fmt.Println("NETWORK=NONE (all probes failed, hermetic)")
	os.Exit(0)
}
