// Differential adversarial substrate -- Go canon probe (gowebpki/jcs v1.0.1).
// Contract: see probe_python.py. Emits "<id>\t h:<hex> | R:<reason>" per case.
// jcs.Transform parses AND canonicalizes raw bytes -- idiomatic Go usage.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gowebpki/jcs"
)

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var d struct {
		Cases []struct {
			ID  string `json:"id"`
			Raw string `json:"raw"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		panic(err)
	}
	for _, c := range d.Cases {
		canon, err := jcs.Transform([]byte(c.Raw))
		if err != nil {
			fmt.Printf("%s\tR:err\n", c.ID)
			continue
		}
		sum := sha256.Sum256(canon)
		fmt.Printf("%s\th:%s\n", c.ID, hex.EncodeToString(sum[:]))
	}
}
