// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE at the repo root.
//
// jws_anchor_v1 signature + anchor runner (Go, stdlib only: crypto/ed25519, crypto/sha256).
//
// Asserts the two things the set exists to pin, for every signed vector:
//   1. the compact JWS signature verifies under the RFC 8032 section 7.1 public key
//   2. the anchor is sha256 of the RAW SIGNED BYTES, never a re-serialised object
// For the SD-JWT vectors the signature covers the JWT segment before the first '~',
// while the anchor is taken over the exact token form the vector names.
//
// Usage: go run sig_runner_go.go <jws_anchor_v1.json>
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type vector struct {
	VectorID         string `json:"vector_id"`
	AnchorRule       string `json:"anchor_rule"`
	Input            string `json:"input"`
	IssuerJWT        string `json:"issuer_jwt"`
	Presentation     string `json:"presentation"`
	ExpectedAnchor   string `json:"expected_anchor"`
	PresentationHash string `json:"presentation_hash"`
}

type set struct {
	SigningKey struct {
		PublicKeyHex string `json:"public_key_hex"`
	} `json:"signing_key"`
	Vectors []json.RawMessage `json:"vectors"`
}

func b64urlDecode(s string) ([]byte, error) {
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(s)
}

func strip(h string) string {
	if i := strings.Index(h, ":"); i >= 0 {
		return h[i+1:]
	}
	return h
}

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("cannot read set:", err)
		os.Exit(2)
	}
	var s set
	if err := json.Unmarshal(raw, &s); err != nil {
		fmt.Println("bad json:", err)
		os.Exit(2)
	}
	pub, err := hex.DecodeString(s.SigningKey.PublicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fmt.Println("bad public key")
		os.Exit(2)
	}

	pass, fail := 0, 0
	check := func(id, what string, ok bool) {
		if ok {
			pass++
		} else {
			fail++
			fmt.Printf("  FAIL %s (%s)\n", id, what)
		}
	}

	for _, rv := range s.Vectors {
		var v vector
		if err := json.Unmarshal(rv, &v); err != nil {
			continue
		}
		if v.AnchorRule != "signed_bytes" {
			continue
		}
		// the token this vector anchors, and the JWT the signature covers
		token := v.Input
		if token == "" {
			token = v.IssuerJWT
		}
		if token == "" {
			token = v.Presentation
		}
		if token == "" {
			continue // e.g. the recanon-negative vector carries no token of its own
		}
		jwt := strings.SplitN(token, "~", 2)[0]

		parts := strings.Split(jwt, ".")
		if len(parts) != 3 {
			check(v.VectorID, "not a compact JWS", false)
			continue
		}
		sig, err := b64urlDecode(parts[2])
		if err != nil {
			check(v.VectorID, "bad signature encoding", false)
			continue
		}
		signingInput := parts[0] + "." + parts[1]
		check(v.VectorID, "ed25519 verify", ed25519.Verify(ed25519.PublicKey(pub), []byte(signingInput), sig))

		// anchor over the raw signed bytes of the exact token form named by the vector
		want := v.ExpectedAnchor
		if want == "" {
			want = v.PresentationHash
		}
		if want != "" {
			sum := sha256.Sum256([]byte(token))
			check(v.VectorID, "anchor = sha256(raw signed bytes)", hex.EncodeToString(sum[:]) == strip(want))
		}
	}

	fmt.Printf("%d/%d PASS\n", pass, pass+fail)
	if fail > 0 {
		os.Exit(1)
	}
}
