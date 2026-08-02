# Keystone L3 fail-closed gauntlet -- Ruby impl (json-canonicalization).
# Independent reimplementation of decision_audit_ref (no algovoi import).
# Usage: ruby gauntlet_ruby.rb <keystone_decision_audit_v1.json>
require "json"
require "json/canonicalization"
require "digest"

REF = /\Asha256:[0-9a-f]{64}\z/

def decision_audit_ref(dr, pcr, mr, pbr, sbr = nil)
  { "decision_ref" => dr, "passport_credential_ref" => pcr, "mandate_ref" => mr, "policy_bound_ref" => pbr }.each do |k, v|
    raise "#{k} must be sha256: ref" unless v.is_a?(String) && v =~ REF
  end
  obj = { "decision_ref" => dr, "passport_credential_ref" => pcr, "mandate_ref" => mr, "policy_bound_ref" => pbr }
  unless sbr.nil?
    raise "screen_binding_ref must be sha256: ref" unless sbr.is_a?(String) && sbr =~ REF
    obj["screen_binding_ref"] = sbr
  end
  "sha256:" + Digest::SHA256.hexdigest(obj.to_json_c14n)
end

d = JSON.parse(File.read(ARGV[0], encoding: "utf-8"))
ok = 0
fails = []
d["vectors"].each do |v|
  got = decision_audit_ref(v["decision_ref"], v["passport_credential_ref"], v["mandate_ref"], v["policy_bound_ref"], v["screen_binding_ref"])
  got == v["expected_decision_audit_ref"] ? ok += 1 : fails << "#{v['id']}: accept-mismatch"
end
d["negatives"].each do |n|
  if n["must"] == "reject"
    begin
      decision_audit_ref(n["decision_ref"], n["passport_credential_ref"], n["mandate_ref"], n["policy_bound_ref"], n["screen_binding_ref"])
      fails << "#{n['id']}: invalid ACCEPTED"
    rescue StandardError
      ok += 1
    end
  else
    got = decision_audit_ref(n["decision_ref"], n["passport_credential_ref"], n["mandate_ref"], n["policy_bound_ref"], n["screen_binding_ref"])
    got != n["claimed_decision_audit_ref"] ? ok += 1 : fails << "#{n['id']}: tamper NOT detected"
  end
end
v0 = d["vectors"][0]
a = decision_audit_ref(v0["decision_ref"], v0["passport_credential_ref"], v0["mandate_ref"], v0["policy_bound_ref"], v0["screen_binding_ref"])
b = decision_audit_ref(v0["decision_ref"], v0["passport_credential_ref"], v0["mandate_ref"], v0["policy_bound_ref"], nil)
a != b ? ok += 1 : fails << "screen-distinctness collision"
begin
  decision_audit_ref("bad", v0["passport_credential_ref"], v0["mandate_ref"], v0["policy_bound_ref"])
  fails << "malformed-ref accepted"
rescue StandardError
  ok += 1
end

total = d["vectors"].size + d["negatives"].size + 2
fails.each { |f| puts "  FAIL #{f}" }
puts "KEYSTONE-GAUNTLET ruby #{ok}/#{total}"
exit(ok == total && fails.empty? ? 0 : 1)
