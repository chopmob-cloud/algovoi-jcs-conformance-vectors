// trust_gate deny-table gauntlet -- Go impl.
package main
import ("encoding/json";"fmt";"os")
var deny = map[string]map[string]bool{
	"block_untrusted": {"UNTRUSTED": true},
	"require_trusted":  {"UNTRUSTED": true, "PROVISIONAL": true, "INSUFFICIENT_EVIDENCE": true},
}
func blocks(mode interface{}, verdict string) bool {
	m, ok := mode.(string)
	if !ok || m == "" || m == "off" { return false }
	return deny[m][verdict]
}
func main() {
	raw, _ := os.ReadFile(os.Args[1])
	var d struct{ Vectors []struct{ ID string `json:"id"`; Mode interface{} `json:"mode"`; Verdict string `json:"verdict"`; ExpectedBlocks bool `json:"expected_blocks"` } `json:"vectors"` }
	json.Unmarshal(raw, &d)
	ok := 0; var fails []string
	for _, v := range d.Vectors { if blocks(v.Mode, v.Verdict) == v.ExpectedBlocks { ok++ } else { fails = append(fails, v.ID+": mismatch") } }
	for _, f := range fails { fmt.Println("  FAIL", f) }
	fmt.Printf("TRUST-GATE-GAUNTLET go %d/%d\n", ok, len(d.Vectors))
	if ok != len(d.Vectors) || len(fails) > 0 { os.Exit(1) }
}
