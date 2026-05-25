// Generic vector-set runner (Go / gowebpki/jcs v1.0.1).
//
// Usage:  go run runner_go.go <vector_set_json>
// One-off: go mod init script-lang-runner && go get github.com/gowebpki/jcs@v1.0.1
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

type Vector struct {
	VectorID                string                 `json:"vector_id"`
	Receipt                 map[string]interface{} `json:"receipt"`
	Response                map[string]interface{} `json:"response"`
	Row                     map[string]interface{} `json:"row"`
	ExpectedJCSBytesB64     string                 `json:"expected_jcs_bytes_b64"`
	ExpectedContentHash     string                 `json:"expected_content_hash"`
	ExpectedRowContentHash  string                 `json:"expected_row_content_hash"`
}

type Set struct {
	Vectors []Vector `json:"vectors"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: runner_go <vector_set_json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var set Set
	if err := json.Unmarshal(raw, &set); err != nil {
		panic(err)
	}
	pass, fail := 0, 0
	for _, v := range set.Vectors {
		var payload map[string]interface{}
		if v.Receipt != nil {
			payload = v.Receipt
		} else if v.Response != nil {
			payload = v.Response
		} else if v.Row != nil {
			payload = v.Row
		} else {
			continue
		}
		buf, err := json.Marshal(payload)
		if err != nil {
			fmt.Printf("  FAIL %s (marshal: %v)\n", v.VectorID, err)
			fail++
			continue
		}
		canon, err := jcs.Transform(buf)
		if err != nil {
			fmt.Printf("  FAIL %s (jcs: %v)\n", v.VectorID, err)
			fail++
			continue
		}
		b64 := base64.StdEncoding.EncodeToString(canon)
		sum := sha256.Sum256(canon)
		digest := hex.EncodeToString(sum[:])
		expectedHash := v.ExpectedContentHash
		if expectedHash == "" {
			expectedHash = v.ExpectedRowContentHash
		}
		if b64 == v.ExpectedJCSBytesB64 && digest == expectedHash {
			pass++
		} else {
			fmt.Printf("  FAIL %s\n", v.VectorID)
			fail++
		}
	}
	fmt.Printf("%d/%d PASS\n", pass, pass+fail)
	if fail > 0 {
		os.Exit(1)
	}
}
