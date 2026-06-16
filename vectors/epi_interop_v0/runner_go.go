// epi_interop_v0 runner -- Go / gowebpki/jcs v1.0.1
//
// Validates sha256(JCS(input)) == frame_id for each vector
//
// Usage (from epi_interop_v0/):
//   go run runner_go.go
//   (reads epi_interop_v0.json from the same directory)
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/gowebpki/jcs"
)

type Vector struct {
	ID                  string                 `json:"id"`
	Input               map[string]interface{} `json:"input"`
	ExpectedJCSBytesB64 string                 `json:"expected_jcs_bytes_b64"`
	FrameID             string                 `json:"frame_id"`
}

type Set struct {
	Vectors []Vector `json:"vectors"`
}

func main() {
	_, thisFile, _, _ := runtime.Caller(0)
	vecFile := filepath.Join(filepath.Dir(thisFile), "epi_interop_v0.json")
	if len(os.Args) > 1 {
		vecFile = os.Args[1]
	}

	raw, err := os.ReadFile(vecFile)
	if err != nil {
		panic(err)
	}
	var set Set
	if err := json.Unmarshal(raw, &set); err != nil {
		panic(err)
	}

	pass, fail := 0, 0
	for _, v := range set.Vectors {
		rawJSON, _ := json.Marshal(v.Input)
		canon, err := jcs.Transform(rawJSON)
		if err != nil {
			fmt.Printf("  FAIL %s (jcs: %v)\n", v.ID, err)
			fail++
			continue
		}
		b64 := base64.StdEncoding.EncodeToString(canon)
		sum := sha256.Sum256(canon)
		ref := "sha256:" + hex.EncodeToString(sum[:])

		if b64 == v.ExpectedJCSBytesB64 && ref == v.FrameID {
			pass++
		} else {
			fail++
			if b64 != v.ExpectedJCSBytesB64 { fmt.Printf("  FAIL %s jcs_bytes_b64 mismatch\n", v.ID) }
			if ref != v.FrameID             { fmt.Printf("  FAIL %s frame_id (got %s)\n", v.ID, ref) }
		}
	}
	fmt.Printf("%d/%d PASS\n", pass, pass+fail)
	if fail > 0 {
		os.Exit(1)
	}
}
