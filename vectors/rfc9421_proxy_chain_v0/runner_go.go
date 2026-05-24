// runner_go.go -- RFC 9421 + RFC 9530 cross-validation runner for the
// rfc9421_proxy_chain_v0 fixture.
//
// Uses Go stdlib only: crypto/ed25519, crypto/sha256, encoding/base64,
// encoding/hex, encoding/json.
//
// Run from the directory containing request.fixture.json:
//   go run runner_go.go
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

type Fixture struct {
	Keypair struct {
		PublicKeyHex string `json:"public_key_hex"`
	} `json:"keypair"`
	Request struct {
		Method    string            `json:"method"`
		Path      string            `json:"path"`
		Authority string            `json:"authority"`
		Headers   map[string]string `json:"headers"`
	} `json:"request"`
	Signing struct {
		SigningBase      string `json:"signing_base"`
		SignatureValueB64 string `json:"signature_value_b64"`
	} `json:"signing"`
}

func parseSignatureInput(value string) ([]string, map[string]string) {
	// Accept both labelled (sig=(...)) and unlabelled ((...)) forms
	body := value
	if idx := strings.Index(value, "=("); idx > 0 {
		body = value[idx+1:]
	}
	closeIdx := strings.Index(body, ")")
	inside := body[1:closeIdx]
	params := body[closeIdx+1:]
	params = strings.TrimPrefix(params, ";")

	re := regexp.MustCompile(`"([^"]+)"`)
	matches := re.FindAllStringSubmatch(inside, -1)
	covered := make([]string, 0, len(matches))
	for _, m := range matches {
		covered = append(covered, m[1])
	}

	paramMap := make(map[string]string)
	for _, kv := range strings.Split(params, ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 {
			paramMap[parts[0]] = strings.Trim(parts[1], `"`)
		}
	}
	return covered, paramMap
}

func parseSignatureValue(value string) ([]byte, error) {
	body := value
	if idx := strings.Index(value, "=:"); idx > 0 {
		body = value[idx+2:]
	} else if strings.HasPrefix(value, ":") {
		body = value[1:]
	}
	body = strings.TrimSuffix(body, ":")
	return base64.StdEncoding.DecodeString(body)
}

func buildSigningBase(covered []string, params map[string]string, fix *Fixture) string {
	var sb strings.Builder
	for i, name := range covered {
		var val string
		switch name {
		case "@method":
			val = strings.ToLower(fix.Request.Method)
		case "@authority":
			val = strings.ToLower(fix.Request.Authority)
		case "@path":
			val = fix.Request.Path
		case "created":
			val = params["created"]
		default:
			val = fix.Request.Headers[name]
		}
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(fmt.Sprintf("\"%s\": %s", name, val))
	}
	return sb.String()
}

func main() {
	data, err := os.ReadFile("request.fixture.json")
	if err != nil {
		fmt.Println("[FAIL] read fixture:", err)
		os.Exit(1)
	}
	var fix Fixture
	if err := json.Unmarshal(data, &fix); err != nil {
		fmt.Println("[FAIL] parse fixture:", err)
		os.Exit(1)
	}

	covered, params := parseSignatureInput(fix.Request.Headers["signature-input"])
	signingBase := buildSigningBase(covered, params, &fix)

	if signingBase != fix.Signing.SigningBase {
		fmt.Println("[FAIL] signing base byte mismatch")
		fmt.Printf("  expected: %q\n  got:      %q\n", fix.Signing.SigningBase, signingBase)
		os.Exit(1)
	}
	fmt.Println("[OK] signing base byte-identical to fixture")

	// Content-Digest of empty body
	h := sha256.Sum256([]byte{})
	expected := "sha-256=:" + base64.StdEncoding.EncodeToString(h[:]) + ":"
	if expected != fix.Request.Headers["content-digest"] {
		fmt.Println("[FAIL] content-digest mismatch")
		os.Exit(1)
	}
	fmt.Println("[OK] RFC 9530 content-digest verified")

	pubBytes, err := hex.DecodeString(fix.Keypair.PublicKeyHex)
	if err != nil {
		fmt.Println("[FAIL] pubkey hex decode:", err)
		os.Exit(1)
	}
	sigBytes, err := parseSignatureValue(fix.Request.Headers["signature"])
	if err != nil {
		fmt.Println("[FAIL] signature decode:", err)
		os.Exit(1)
	}
	ok := ed25519.Verify(ed25519.PublicKey(pubBytes), []byte(signingBase), sigBytes)
	if !ok {
		fmt.Println("[FAIL] Ed25519 verify failed")
		os.Exit(1)
	}
	fmt.Println("[OK] Ed25519 signature verified")
	fmt.Println("PASS (Go stdlib: crypto/ed25519 + crypto/sha256)")
}
