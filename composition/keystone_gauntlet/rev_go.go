// revocation_ref fail-closed gauntlet -- Go impl (gowebpki/jcs).
package main
import ("crypto/sha256";"encoding/hex";"encoding/json";"errors";"fmt";"math";"os";"regexp";"github.com/gowebpki/jcs")
var refRe=regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var reasons=map[string]bool{"USER_REQUESTED":true,"COMPLIANCE_TRIGGERED":true,"EXPIRED":true,"KEY_COMPROMISE":true,"SUPERSEDED":true,"ADMIN":true}
var status=map[string]bool{"active":true,"suspended":true,"revoked":true,"inactive":true}
func hjcs(o interface{}) (string,error){ raw,_:=json.Marshal(o); c,e:=jcs.Transform(raw); if e!=nil{return "",e}; s:=sha256.Sum256(c); return "sha256:"+hex.EncodeToString(s[:]),nil }
func rref(f map[string]interface{}) (string,error){
	rr:=func(k string)(string,error){ s,ok:=f[k].(string); if !ok||!refRe.MatchString(s){return "",errors.New(k)}; return s,nil }
	ri:=func(k string)(int64,error){ x,ok:=f[k].(float64); if !ok||x!=math.Trunc(x)||x<0{return 0,errors.New(k)}; return int64(x),nil }
	renum:=func(k string,m map[string]bool)(string,error){ s,ok:=f[k].(string); if !ok||!m[s]{return "",errors.New(k)}; return s,nil }
	rs:=func(k string)(string,error){ s,ok:=f[k].(string); if !ok||s==""{return "",errors.New(k)}; return s,nil }
	sr,e:=rr("subject_ref"); if e!=nil{return "",e}
	rm,e:=ri("revoked_at_ms"); if e!=nil{return "",e}
	rc,e:=renum("reason_code",reasons); if e!=nil{return "",e}
	id,e:=rs("issuer_did"); if e!=nil{return "",e}
	ps,e:=renum("prev_status",status); if e!=nil{return "",e}
	ns,e:=renum("new_status",status); if e!=nil{return "",e}
	sq,e:=ri("seq"); if e!=nil{return "",e}
	var prev interface{}=nil
	if p,present:=f["prev_revocation_ref"]; present&&p!=nil { s,ok:=p.(string); if !ok||!refRe.MatchString(s){return "",errors.New("prev")}; prev=s }
	obj:=map[string]interface{}{"canon_version":"jcs-rfc8785-v1","type":"revocation_link","subject_ref":sr,"revoked_at_ms":rm,"reason_code":rc,"issuer_did":id,"prev_status":ps,"new_status":ns,"seq":sq,"prev_revocation_ref":prev}
	return hjcs(obj)
}
func vchain(links []map[string]interface{}) bool {
	var prev interface{}=nil
	for i,l:=range links {
		sq,ok:=l["seq"].(float64); if !ok||int(sq)!=i { return false }
		if l["prev_revocation_ref"]!=prev { return false }
		r,e:=hjcs(l); if e!=nil{return false}; prev=r
	}
	return true
}
func main(){
	raw,_:=os.ReadFile(os.Args[1])
	var d struct{ Vectors []map[string]interface{} `json:"vectors"`; Negatives []map[string]interface{} `json:"negatives"`; Tamper []map[string]interface{} `json:"tamper"`; ChainValid []struct{ ID string `json:"id"`; Links []map[string]interface{} `json:"links"` } `json:"chain_valid"`; ChainInvalid []struct{ ID string `json:"id"`; Links []map[string]interface{} `json:"links"` } `json:"chain_invalid"` }
	json.Unmarshal(raw,&d)
	ok:=0; var fails []string
	for _,v:=range d.Vectors { r,e:=rref(v); if e==nil&&r==v["expected_revocation_ref"].(string){ok++}else{fails=append(fails,v["id"].(string))} }
	for _,n:=range d.Negatives { if _,e:=rref(n);e!=nil{ok++}else{fails=append(fails,n["id"].(string))} }
	for _,t:=range d.Tamper { r,_:=rref(t); if r!=t["claimed_revocation_ref"].(string){ok++}else{fails=append(fails,t["id"].(string))} }
	for _,c:=range d.ChainValid { if vchain(c.Links){ok++}else{fails=append(fails,c.ID)} }
	for _,c:=range d.ChainInvalid { if !vchain(c.Links){ok++}else{fails=append(fails,c.ID)} }
	total:=len(d.Vectors)+len(d.Negatives)+len(d.Tamper)+len(d.ChainValid)+len(d.ChainInvalid)
	for _,f:=range fails{ fmt.Println("  FAIL",f) }
	fmt.Printf("REVOCATION-GAUNTLET go %d/%d\n", ok, total)
	if ok!=total||len(fails)>0 { os.Exit(1) }
}
