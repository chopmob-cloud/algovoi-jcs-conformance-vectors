# revocation_ref fail-closed gauntlet -- Ruby impl (json-canonicalization).
require "json"; require "json/canonicalization"; require "digest"
REF=/\Asha256:[0-9a-f]{64}\z/
REASONS=%w[USER_REQUESTED COMPLIANCE_TRIGGERED EXPIRED KEY_COMPROMISE SUPERSEDED ADMIN]
STATUS=%w[active suspended revoked inactive]
def rr(v); raise unless v.is_a?(String)&&v=~REF; v; end
def ri(v); raise if v==true||v==false; raise unless v.is_a?(Integer)&&v>=0; v; end
def re_(v,a); raise unless a.include?(v); v; end
def rs(v); raise unless v.is_a?(String)&&v!=""; v; end
def h(o); "sha256:"+Digest::SHA256.hexdigest(o.to_json_c14n); end
def rref(f)
  p=f["prev_revocation_ref"]
  h({"canon_version"=>"jcs-rfc8785-v1","type"=>"revocation_link","subject_ref"=>rr(f["subject_ref"]),
     "revoked_at_ms"=>ri(f["revoked_at_ms"]),"reason_code"=>re_(f["reason_code"],REASONS),
     "issuer_did"=>rs(f["issuer_did"]),"prev_status"=>re_(f["prev_status"],STATUS),
     "new_status"=>re_(f["new_status"],STATUS),"seq"=>ri(f["seq"]),
     "prev_revocation_ref"=>p.nil? ? nil : rr(p)})
end
def vchain(links); prev=nil; links.each_with_index{|l,i| return false if l["seq"]!=i||l["prev_revocation_ref"]!=prev; prev=h(l)}; true; end
d=JSON.parse(File.read(ARGV[0],encoding:"utf-8")); ok=0; fails=[]
d["vectors"].each{|v| begin; rref(v)==v["expected_revocation_ref"] ? ok+=1 : fails<<v["id"]; rescue StandardError; fails<<v["id"]; end}
d["negatives"].each{|n| begin; rref(n); fails<<n["id"]; rescue StandardError; ok+=1; end}
d["tamper"].each{|t| rref(t)!=t["claimed_revocation_ref"] ? ok+=1 : fails<<t["id"]}
d["chain_valid"].each{|c| vchain(c["links"]) ? ok+=1 : fails<<c["id"]}
d["chain_invalid"].each{|c| !vchain(c["links"]) ? ok+=1 : fails<<c["id"]}
total=d["vectors"].size+d["negatives"].size+d["tamper"].size+d["chain_valid"].size+d["chain_invalid"].size
fails.each{|f| puts "  FAIL #{f}"}
puts "REVOCATION-GAUNTLET ruby #{ok}/#{total}"
exit(ok==total && fails.empty? ? 0 : 1)
