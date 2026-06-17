// Generic preimage runner (Go / gowebpki/jcs). Usage: go run runner_go.go <set.json>
package main
import ("crypto/sha256";"encoding/base64";"encoding/hex";"encoding/json";"fmt";"os";"github.com/gowebpki/jcs")
type Vec struct {
  VectorID string `json:"vector_id"`
  Preimage map[string]interface{} `json:"preimage"`
  ExpB64 string `json:"expected_jcs_bytes_b64"`
  ExpCS string `json:"expected_content_sha256"`
  ExpTH string `json:"expected_transition_hash"`
  ExpAR string `json:"expected_action_ref"`
}
type Set struct { Vectors []Vec `json:"vectors"` }
func main(){
  raw,_ := os.ReadFile(os.Args[1]); var s Set; json.Unmarshal(raw,&s)
  p,q := 0,0
  for _,v := range s.Vectors {
    if v.Preimage==nil { continue }
    buf,_ := json.Marshal(v.Preimage); canon,err := jcs.Transform(buf)
    if err!=nil { q++; fmt.Printf("  FAIL %s (jcs)\n",v.VectorID); continue }
    b64 := base64.StdEncoding.EncodeToString(canon); sum := sha256.Sum256(canon); dg := hex.EncodeToString(sum[:])
    eh := v.ExpCS; if eh=="" { eh = v.ExpTH }; if eh=="" { eh = v.ExpAR }
    if b64==v.ExpB64 && dg==eh { p++ } else { q++; fmt.Printf("  FAIL %s\n",v.VectorID) }
  }
  fmt.Printf("%d/%d PASS\n",p,p+q); if q>0 { os.Exit(1) }
}
