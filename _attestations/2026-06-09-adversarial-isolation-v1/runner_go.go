// Generic input runner (Go / gowebpki/jcs). Claim 1 (input bytes) only.
// json.RawMessage so `input` can be an object OR an array (audit_chain).
// Usage: go run runner_go.go <set.json>
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gowebpki/jcs"
)

type Vec struct {
	VectorID string          `json:"vector_id"`
	Input    json.RawMessage `json:"input"`
	ExpB64   string          `json:"input_jcs_bytes_b64"`
	ExpSha   string          `json:"input_content_sha256"`
}
type Set struct {
	Vectors []Vec `json:"vectors"`
}

func main() {
	raw, _ := os.ReadFile(os.Args[1])
	var s Set
	json.Unmarshal(raw, &s)
	p, q := 0, 0
	for _, v := range s.Vectors {
		if len(v.Input) == 0 {
			continue
		}
		canon, err := jcs.Transform(v.Input)
		if err != nil {
			q++
			fmt.Printf("  FAIL %s (jcs)\n", v.VectorID)
			continue
		}
		b64 := base64.StdEncoding.EncodeToString(canon)
		sum := sha256.Sum256(canon)
		dg := hex.EncodeToString(sum[:])
		if b64 == v.ExpB64 && dg == v.ExpSha {
			p++
		} else {
			q++
			fmt.Printf("  FAIL %s\n", v.VectorID)
		}
	}
	fmt.Printf("%d/%d PASS\n", p, p+q)
	if q > 0 {
		os.Exit(1)
	}
}
