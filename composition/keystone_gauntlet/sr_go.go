// settlement_round validity gauntlet -- Go impl.
package main
import ("encoding/json";"errors";"fmt";"math";"os")
func rpi(v interface{}) error {
	switch t := v.(type) {
	case bool: return errors.New("bool")
	case float64: if t != math.Trunc(t) || t <= 0 { return errors.New("not positive int") }; return nil
	default: return errors.New("not int")
	}
}
func main() {
	raw, _ := os.ReadFile(os.Args[1])
	var d struct {
		Rejects []map[string]interface{} `json:"settlement_round_reject_vectors"`
		Vectors []map[string]interface{} `json:"vectors"`
	}
	json.Unmarshal(raw, &d)
	ok := 0; var fails []string
	for _, r := range d.Rejects {
		rc := r["receipt"].(map[string]interface{})
		if rpi(rc["settlement_round"]) != nil { ok++ } else { fails = append(fails, r["vector_id"].(string)+": bad round ACCEPTED") }
	}
	var acc map[string]interface{}
	for _, v := range d.Vectors {
		if rc, o := v["receipt"].(map[string]interface{}); o {
			if f, isf := rc["settlement_round"].(float64); isf && f == math.Trunc(f) && f > 0 { acc = v; break }
		}
	}
	rc := acc["receipt"].(map[string]interface{})
	if rpi(rc["settlement_round"]) == nil { ok++ } else { fails = append(fails, acc["vector_id"].(string)+": valid round REJECTED") }
	total := len(d.Rejects) + 1
	for _, f := range fails { fmt.Println("  FAIL", f) }
	fmt.Printf("SETTLEMENT-ROUND-GAUNTLET go %d/%d\n", ok, total)
	if ok != total || len(fails) > 0 { os.Exit(1) }
}
