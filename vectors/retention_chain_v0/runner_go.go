// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE in this directory.
// Retention Chain v0 vector runner -- Go / gowebpki/jcs v1.0.1
//
// Usage:  go run runner_go.go <vector_set_json>
// Setup:  go mod init retention-chain-runner && go get github.com/gowebpki/jcs@v1.0.1
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
	VectorID             string                 `json:"vector_id"`
	Preimage             map[string]interface{} `json:"preimage"`
	ExpectedJCSBytesB64  string                 `json:"expected_jcs_bytes_b64"`
	ExpectedChainRef     string                 `json:"expected_chain_ref"`
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
		b64, ref, err := sha256Jcs(v.Preimage)
		if err != nil {
			fmt.Printf("  FAIL %s (jcs: %v)\n", v.VectorID, err)
			fail++
			continue
		}
		b64Ok := b64 == v.ExpectedJCSBytesB64
		refOk := ref == v.ExpectedChainRef
		if b64Ok && refOk {
			pass++
		} else {
			fail++
			if !b64Ok { fmt.Printf("  FAIL %s jcs_bytes_b64 mismatch\n", v.VectorID) }
			if !refOk  { fmt.Printf("  FAIL %s chain_ref (got %s)\n", v.VectorID, ref) }
		}
	}
	fmt.Printf("%d/%d PASS\n", pass, pass+fail)
	if fail > 0 {
		os.Exit(1)
	}
}
