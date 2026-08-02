// Keystone L3 fail-closed gauntlet -- Go impl (gowebpki/jcs v1.0.1).
// Independent reimplementation of decision_audit_ref (no algovoi import).
// Usage: go run gauntlet_go.go <keystone_decision_audit_v1.json>
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/gowebpki/jcs"
)

var refRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func decisionAuditRef(m map[string]interface{}) (string, error) {
	obj := map[string]interface{}{}
	for _, k := range []string{"decision_ref", "passport_credential_ref", "mandate_ref", "policy_bound_ref"} {
		s, ok := m[k].(string)
		if !ok || !refRe.MatchString(s) {
			return "", errors.New(k + " must be sha256: ref")
		}
		obj[k] = s
	}
	if sbr, present := m["screen_binding_ref"]; present && sbr != nil {
		s, ok := sbr.(string)
		if !ok || !refRe.MatchString(s) {
			return "", errors.New("screen_binding_ref must be sha256: ref")
		}
		obj["screen_binding_ref"] = s
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
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var d struct {
		Vectors   []map[string]interface{} `json:"vectors"`
		Negatives []map[string]interface{} `json:"negatives"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		panic(err)
	}
	ok := 0
	var fails []string
	for _, v := range d.Vectors {
		got, err := decisionAuditRef(v)
		if err == nil && got == v["expected_decision_audit_ref"].(string) {
			ok++
		} else {
			fails = append(fails, v["id"].(string)+": accept-mismatch")
		}
	}
	for _, n := range d.Negatives {
		must, _ := n["must"].(string)
		if must == "reject" {
			if _, err := decisionAuditRef(n); err != nil {
				ok++
			} else {
				fails = append(fails, n["id"].(string)+": invalid ACCEPTED")
			}
		} else {
			got, _ := decisionAuditRef(n)
			if got != n["claimed_decision_audit_ref"].(string) {
				ok++
			} else {
				fails = append(fails, n["id"].(string)+": tamper NOT detected")
			}
		}
	}
	v0 := d.Vectors[0]
	a, _ := decisionAuditRef(v0)
	noScreen := map[string]interface{}{}
	for k, v := range v0 {
		if k != "screen_binding_ref" {
			noScreen[k] = v
		}
	}
	b, _ := decisionAuditRef(noScreen)
	if a != b {
		ok++
	} else {
		fails = append(fails, "screen-distinctness collision")
	}
	bad := map[string]interface{}{"decision_ref": "bad", "passport_credential_ref": v0["passport_credential_ref"], "mandate_ref": v0["mandate_ref"], "policy_bound_ref": v0["policy_bound_ref"]}
	if _, err := decisionAuditRef(bad); err != nil {
		ok++
	} else {
		fails = append(fails, "malformed-ref accepted")
	}
	total := len(d.Vectors) + len(d.Negatives) + 2
	for _, f := range fails {
		fmt.Println("  FAIL", f)
	}
	fmt.Printf("KEYSTONE-GAUNTLET go %d/%d\n", ok, total)
	if ok != total || len(fails) > 0 {
		os.Exit(1)
	}
}
