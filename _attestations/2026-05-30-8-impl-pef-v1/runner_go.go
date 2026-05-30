// PEF v1 vector runner -- Go / gowebpki/jcs v1.0.1
//
// Usage:  go run runner_go.go <vector_set_json>
// One-off: go mod init pef-runner && go get github.com/gowebpki/jcs@v1.0.1
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
	VectorID                    string                 `json:"vector_id"`
	Receipt                     map[string]interface{} `json:"receipt"`
	Preimage                    map[string]interface{} `json:"preimage"`
	ExpectedReceiptJCSBytesB64  string                 `json:"expected_receipt_jcs_bytes_b64"`
	ExpectedReceiptHash         string                 `json:"expected_receipt_hash"`
	ExpectedPreimageJCSBytesB64 string                 `json:"expected_preimage_jcs_bytes_b64"`
	ExpectedFrameID             string                 `json:"expected_frame_id"`
}

type Set struct {
	Vectors []Vector `json:"vectors"`
}

func sha256Jcs(obj map[string]interface{}) (string, string, error) {
	raw, err := json.Marshal(obj)
	if err != nil {
		return "", "", err
	}
	canon, err := jcs.Transform(raw)
	if err != nil {
		return "", "", err
	}
	b64 := base64.StdEncoding.EncodeToString(canon)
	sum := sha256.Sum256(canon)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	return b64, digest, nil
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
		r_b64, r_hash, err := sha256Jcs(v.Receipt)
		if err != nil {
			fmt.Printf("  FAIL %s (receipt jcs: %v)\n", v.VectorID, err)
			fail++
			continue
		}
		p_b64, p_hash, err := sha256Jcs(v.Preimage)
		if err != nil {
			fmt.Printf("  FAIL %s (preimage jcs: %v)\n", v.VectorID, err)
			fail++
			continue
		}

		receiptOk  := r_b64 == v.ExpectedReceiptJCSBytesB64 && r_hash == v.ExpectedReceiptHash
		preimageOk := p_b64 == v.ExpectedPreimageJCSBytesB64 && p_hash == v.ExpectedFrameID

		if receiptOk && preimageOk {
			pass++
		} else {
			fail++
			if !receiptOk  { fmt.Printf("  FAIL %s receipt_hash\n", v.VectorID) }
			if !preimageOk { fmt.Printf("  FAIL %s frame_id (got %s)\n", v.VectorID, p_hash) }
		}
	}
	fmt.Printf("%d/%d PASS\n", pass, pass+fail)
	if fail > 0 {
		os.Exit(1)
	}
}
