# Generic preimage runner (Ruby / json-canonicalization). Usage: ruby runner_ruby.rb <set.json>
require "json"; require "json/canonicalization"; require "digest"; require "base64"
data = JSON.parse(File.read(ARGV[0], encoding: "utf-8"))
p = 0; q = 0
data["vectors"].each do |v|
  pay = v["preimage"]; next unless pay
  canon = pay.to_json_c14n; bytes = canon.dup.force_encoding("ASCII-8BIT")
  b64 = Base64.strict_encode64(bytes); dg = Digest::SHA256.hexdigest(bytes)
  eh = v["expected_transition_hash"] || v["expected_action_ref"]
  if b64 == v["expected_jcs_bytes_b64"] && dg == eh then p += 1 else q += 1; puts "  FAIL #{v['vector_id']}" end
end
puts "#{p}/#{p+q} PASS"; exit(q == 0 ? 0 : 1)
