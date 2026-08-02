# Keystone L3 gauntlet -- guard_context, Ruby impl (json-canonicalization).
# Usage: ruby gc_ruby.rb <keystone_guard_context_v1.json>
require "json"
require "json/canonicalization"
require "digest"

REF = /\Asha256:[0-9a-f]{64}\z/

def guard_context_ref(ts, policy_ref, mandate_ref, passport_credential_ref)
  raise "guard_timestamp_ms must be non-negative int" unless ts.is_a?(Integer) && ts >= 0
  { "policy_ref" => policy_ref, "mandate_ref" => mandate_ref, "passport_credential_ref" => passport_credential_ref }.each do |k, v|
    raise "#{k} must be sha256: ref" unless v.is_a?(String) && v =~ REF
  end
  obj = { "canon_version" => "jcs-rfc8785-v1", "type" => "guard_context",
          "guard_timestamp_ms" => ts, "policy_ref" => policy_ref,
          "mandate_ref" => mandate_ref, "passport_credential_ref" => passport_credential_ref }
  "sha256:" + Digest::SHA256.hexdigest(obj.to_json_c14n)
end

d = JSON.parse(File.read(ARGV[0], encoding: "utf-8"))
ok = 0
fails = []
d["vectors"].each do |v|
  got = guard_context_ref(v["guard_timestamp_ms"], v["policy_ref"], v["mandate_ref"], v["passport_credential_ref"])
  got == v["expected_guard_context_ref"] ? ok += 1 : fails << "#{v['id']}: accept-mismatch"
end
d["negatives"].each do |n|
  if n["must"] == "reject"
    begin
      guard_context_ref(n["guard_timestamp_ms"], n["policy_ref"], n["mandate_ref"], n["passport_credential_ref"])
      fails << "#{n['id']}: invalid ACCEPTED"
    rescue StandardError
      ok += 1
    end
  else
    got = guard_context_ref(n["guard_timestamp_ms"], n["policy_ref"], n["mandate_ref"], n["passport_credential_ref"])
    got != n["claimed_guard_context_ref"] ? ok += 1 : fails << "#{n['id']}: tamper NOT detected"
  end
end
v0 = d["vectors"][0]
a = guard_context_ref(v0["guard_timestamp_ms"], v0["policy_ref"], v0["mandate_ref"], v0["passport_credential_ref"])
b = guard_context_ref(v0["guard_timestamp_ms"] + 1, v0["policy_ref"], v0["mandate_ref"], v0["passport_credential_ref"])
a != b ? ok += 1 : fails << "moment-distinctness collision"
begin
  guard_context_ref(1720000000000.5, v0["policy_ref"], v0["mandate_ref"], v0["passport_credential_ref"])
  fails << "float-ts accepted"
rescue StandardError
  ok += 1
end

total = d["vectors"].size + d["negatives"].size + 2
fails.each { |f| puts "  FAIL #{f}" }
puts "KEYSTONE-GAUNTLET-GC ruby #{ok}/#{total}"
exit(ok == total && fails.empty? ? 0 : 1)
