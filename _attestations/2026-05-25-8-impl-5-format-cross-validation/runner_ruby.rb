#!/usr/bin/env ruby
# Generic vector-set runner (Ruby / json-canonicalization 1.0.0).
#
# Usage: ruby runner_ruby.rb <vector_set_json>
# Requires: gem install json-canonicalization

require "json"
require "json/canonicalization"
require "digest"
require "base64"

vector_file = ARGV[0]
data = JSON.parse(File.read(vector_file, encoding: "utf-8"))

pass = 0
fail = 0
data["vectors"].each do |v|
  payload = v["receipt"] || v["response"] || v["row"]
  next unless payload
  canon = payload.to_json_c14n
  canon_bytes = canon.dup.force_encoding("ASCII-8BIT")
  b64 = Base64.strict_encode64(canon_bytes)
  digest = Digest::SHA256.hexdigest(canon_bytes)
  expected_hash = v["expected_content_hash"] || v["expected_row_content_hash"]
  if b64 == v["expected_jcs_bytes_b64"] && digest == expected_hash
    pass += 1
  else
    fail += 1
    puts "  FAIL #{v['vector_id']}"
  end
end
puts "#{pass}/#{pass + fail} PASS"
exit(fail == 0 ? 0 : 1)
