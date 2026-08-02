// Keystone L3 gauntlet -- guard_context, Go impl (gowebpki/jcs).
// Usage: go run gc_go.go <keystone_guard_context_v1.json>
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"

	"github.com/gowebpki/jcs"
)

var refRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func guardContextRef(ts interface{}, m map[string]interface{}) (string, error) {
	f, ok := ts.(float64)
	if !ok || f < 0 || f != math.Trunc(f) {
		return "", errors.New("guard_timestamp_ms must be non-negative integer")
	}
	for _, k := range []string{"policy_ref", "mandate_ref", "passport_credential_ref"} {
		s, ok := m[k].(string)
		if !ok || !refRe.MatchString(s) {
			return "", errors.New(k + " must be sha256: ref")
		}
	}
	obj := map[string]interface{}{
		"canon_version": "jcs-rfc8785-v1", "type": "guard_context",
		"guard_timestamp_ms":      int64(f),
		"policy_ref":              m["policy_ref"],
		"mandate_ref":             m["mandate_ref"],
		"passport_credential_ref": m["passport_credential_ref"],
	}
	raw, _ := json.Marshal(obj)
	canon, err := jcs.Transform(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func main() {
	raw, _ := os.ReadFile(os.Args[1])
	var d struct {
		Vectors   []map[string]interface{} `json:"vectors"`
		Negatives []map[string]interface{} `json:"negatives"`
	}
	json.Unmarshal(raw, &d)
	ok := 0
	var fails []string
	for _, v := range d.Vectors {
		got, err := guardContextRef(v["guard_timestamp_ms"], v)
		if err == nil && got == v["expected_guard_context_ref"].(string) {
			ok++
		} else {
			fails = append(fails, v["id"].(string)+": accept-mismatch")
		}
	}
	for _, n := range d.Negatives {
		if n["must"].(string) == "reject" {
			if _, err := guardContextRef(n["guard_timestamp_ms"], n); err != nil {
				ok++
			} else {
				fails = append(fails, n["id"].(string)+": invalid ACCEPTED")
			}
		} else {
			got, _ := guardContextRef(n["guard_timestamp_ms"], n)
			if got != n["claimed_guard_context_ref"].(string) {
				ok++
			} else {
				fails = append(fails, n["id"].(string)+": tamper NOT detected")
			}
		}
	}
	v0 := d.Vectors[0]
	a, _ := guardContextRef(v0["guard_timestamp_ms"], v0)
	b, _ := guardContextRef(v0["guard_timestamp_ms"].(float64)+1, v0)
	if a != b {
		ok++
	} else {
		fails = append(fails, "moment-distinctness collision")
	}
	if _, err := guardContextRef(1720000000000.5, v0); err != nil {
		ok++
	} else {
		fails = append(fails, "float-ts accepted")
	}
	total := len(d.Vectors) + len(d.Negatives) + 2
	for _, f := range fails {
		fmt.Println("  FAIL", f)
	}
	fmt.Printf("KEYSTONE-GAUNTLET-GC go %d/%d\n", ok, total)
	if ok != total || len(fails) > 0 {
		os.Exit(1)
	}
}
