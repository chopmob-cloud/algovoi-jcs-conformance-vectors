// runner_go.go -- RFC 9421 §2.5-CONFORMANT cross-validation runner for the
// rfc9421_proxy_chain_v1 fixture. Independent reimplementation (no AlgoVoi
// package): rebuilds the conformant signing base from scratch and verifies
// with the Go ed25519 stdlib.
//
// Run: go run runner_go.go   (from the dir containing request.fixture.json)
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type fixture struct {
	Request struct {
		Method    string            `json:"method"`
		Path      string            `json:"path"`
		Authority string            `json:"authority"`
		Headers   map[string]string `json:"headers"`
	} `json:"request"`
	Keypair struct {
		PublicKeyHex string `json:"public_key_hex"`
	} `json:"keypair"`
	Signing struct {
		SigningBase string `json:"signing_base"`
	} `json:"signing"`
}

func main() {
	data, err := os.ReadFile("request.fixture.json")
	if err != nil {
		fmt.Println("[FAIL] read fixture:", err)
		os.Exit(1)
	}
	var fix fixture
	if err := json.Unmarshal(data, &fix); err != nil {
		fmt.Println("[FAIL] parse fixture:", err)
		os.Exit(1)
	}

	method := fix.Request.Method // PRESERVE case
	authority := strings.ToLower(fix.Request.Authority)
	path := fix.Request.Path
	cd := fix.Request.Headers["content-digest"]
	si := fix.Request.Headers["signature-input"]
	sigHeader := fix.Request.Headers["signature"]
	expected := fix.Signing.SigningBase

	paramsRaw := si[strings.Index(si, "=")+1:]
	inner := paramsRaw[1:strings.Index(paramsRaw, ")")]
	covered := regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(inner, -1)

	var lines []string
	for _, m := range covered {
		name := m[1]
		var val string
		switch name {
		case "@method":
			val = method
		case "@authority":
			val = authority
		case "@path":
			val = path
		case "content-digest":
			val = cd
		default:
			fmt.Println("unexpected covered component:", name)
			os.Exit(1)
		}
		lines = append(lines, fmt.Sprintf("%q: %s", name, val))
	}
	lines = append(lines, fmt.Sprintf("%q: %s", "@signature-params", paramsRaw))
	base := strings.Join(lines, "\n")

	if base != expected {
		fmt.Println("[FAIL] signing base mismatch")
		fmt.Printf("  expected: %q\n  got:      %q\n", expected, base)
		os.Exit(1)
	}
	fmt.Println("[OK] signing base byte-identical to fixture (rfc9421 conformant)")

	sum := sha256.Sum256([]byte(""))
	expectedCd := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	if expectedCd != cd {
		fmt.Println("[FAIL] content-digest mismatch")
		os.Exit(1)
	}
	fmt.Println("[OK] RFC 9530 content-digest verified")

	pub, _ := hex.DecodeString(fix.Keypair.PublicKeyHex)
	body := strings.TrimSuffix(sigHeader[strings.Index(sigHeader, "=:")+2:], ":")
	sig, _ := base64.StdEncoding.DecodeString(body)
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(base), sig) {
		fmt.Println("[FAIL] Ed25519 verify failed")
		os.Exit(1)
	}
	fmt.Println("[OK] Ed25519 signature verified")
	fmt.Println("PASS (Go: inline conformant base + crypto/ed25519 stdlib)")
}
