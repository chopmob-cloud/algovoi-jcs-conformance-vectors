#!/usr/bin/env ruby
# PEF v1 vector runner -- Ruby / json-canonicalization 1.0.0
#
# Usage: ruby runner_ruby.rb <vector_set_json>
# Requires: gem install json-canonicalization

require "json"
require "json/canonicalization"
require "digest"
require "base64"

def sha256_jcs(obj)
  canon = obj.to_json_c14n
  bytes = canon.dup.force_encoding("ASCII-8BIT")
  b64   = Base64.strict_encode64(bytes)
  hash  = "sha256:" + Digest::SHA256.hexdigest(bytes)
  [b64, hash]
end

data = JSON.parse(File.read(ARGV[0], encoding: "utf-8"))
pass = 0
fail = 0

data["vectors"].each do |v|
  r_b64, r_hash = sha256_jcs(v["receipt"])
  p_b64, p_hash = sha256_jcs(v["preimage"])

  receipt_ok  = r_b64 == v["expected_receipt_jcs_bytes_b64"] &&
                r_hash == v["expected_receipt_hash"]
  preimage_ok = p_b64 == v["expected_preimage_jcs_bytes_b64"] &&
                p_hash == v["expected_frame_id"]

  if receipt_ok && preimage_ok
    pass += 1
  else
    fail += 1
    puts "  FAIL #{v['vector_id']} receipt_hash" unless receipt_ok
    puts "  FAIL #{v['vector_id']} frame_id (got #{p_hash})" unless preimage_ok
  end
end

puts "#{pass}/#{pass + fail} PASS"
exit(fail == 0 ? 0 : 1)
