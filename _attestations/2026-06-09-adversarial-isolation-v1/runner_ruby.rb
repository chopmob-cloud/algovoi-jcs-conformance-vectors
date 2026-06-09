# Generic input runner (Ruby / json-canonicalization). Claim 1 (input bytes) only.
# Usage: ruby runner_ruby.rb <set.json>
require "json"
require "json/canonicalization"
require "digest"
require "base64"

data = JSON.parse(File.read(ARGV[0], encoding: "utf-8"))
p = 0
q = 0
data["vectors"].each do |v|
  obj = v["input"]
  next if obj.nil?
  canon = obj.to_json_c14n
  bytes = canon.dup.force_encoding("ASCII-8BIT")
  if Base64.strict_encode64(bytes) == v["input_jcs_bytes_b64"] && Digest::SHA256.hexdigest(bytes) == v["input_content_sha256"]
    p += 1
  else
    q += 1
    puts "  FAIL #{v['vector_id']}"
  end
end
puts "#{p}/#{p + q} PASS"
exit(q == 0 ? 0 : 1)
