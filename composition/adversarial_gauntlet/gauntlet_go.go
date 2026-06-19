// Adversarial gauntlet runner -- Go (independent reimplementation, no algovoi import).
// Same three checks; must accept the control and reject all 11 mutations.
// Usage: go run gauntlet_go.go /path/to/adversarial_isolation_v1.json
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

var hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

func isHex64(v interface{}) bool {
	s, ok := v.(string)
	return ok && hexRe.MatchString(s)
}

func isUint(v interface{}) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	i, err := n.Int64()
	return err == nil && i >= 0
}

func nestr(v interface{}) bool {
	s, ok := v.(string)
	return ok && len(s) > 0
}

// jcsFlat: json.Marshal sorts map keys and is compact -> byte-identical to RFC 8785
// JCS for the ASCII-string / integer payloads in this vector set.
func jcsFlat(o map[string]interface{}) string {
	b, _ := json.Marshal(o)
	return string(b)
}

func checkTransition(in interface{}) bool {
	o, ok := in.(map[string]interface{})
	if !ok {
		return false
	}
	if !isHex64(o["action_ref"]) || !nestr(o["state"]) {
		return false
	}
	for _, k := range []string{"transition_timestamp_ms", "authority_verified_at_ms", "revocation_check_at_ms"} {
		if !isUint(o[k]) {
			return false
		}
	}
	return true
}

func checkActionRef(in interface{}) bool {
	o, ok := in.(map[string]interface{})
	if !ok {
		return false
	}
	for _, k := range []string{"agent_id", "action_type", "scope"} {
		if !nestr(o[k]) {
			return false
		}
	}
	return isUint(o["timestamp_ms"])
}

func checkAuditChain(in interface{}) bool {
	rows, ok := in.([]interface{})
	if !ok || len(rows) == 0 {
		return false
	}
	prev := ""
	for i, rr := range rows {
		r, ok := rr.(map[string]interface{})
		if !ok {
			return false
		}
		cp, ok := r["chain_position"].(json.Number)
		if !ok {
			return false
		}
		ci, err := cp.Int64()
		if err != nil || ci != int64(i) {
			return false
		}
		if i == 0 {
			if r["prev_hash"] != nil {
				return false
			}
		} else {
			ph, _ := r["prev_hash"].(string)
			if ph != prev {
				return false
			}
		}
		payload, ok := r["payload"].(map[string]interface{})
		if !ok {
			return false
		}
		sum := sha256.Sum256([]byte(jcsFlat(payload)))
		ch, _ := r["content_hash"].(string)
		if fmt.Sprintf("%x", sum) != ch {
			return false
		}
		prev = ch
	}
	return true
}

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]interface{}
	if err := dec.Decode(&doc); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	checks := map[string]func(interface{}) bool{
		"transition_preimage": checkTransition,
		"action_ref":          checkActionRef,
		"audit_chain":         checkAuditChain,
	}
	ok, total := 0, 0
	for _, vv := range doc["vectors"].([]interface{}) {
		v := vv.(map[string]interface{})
		total++
		verdict := "reject"
		if checks[v["check"].(string)](v["input"]) {
			verdict = "accept"
		}
		expected := "accept"
		if v["expectation"] == "reject" {
			expected = "reject"
		}
		good := verdict == expected
		status := "MISMATCH"
		if good {
			ok++
			status = "OK"
		}
		fmt.Printf("%s %s expect=%s %s\n", v["vector_id"], verdict, expected, status)
	}
	fmt.Printf("GAUNTLET go %d/%d\n", ok, total)
	if ok != total {
		os.Exit(1)
	}
}
