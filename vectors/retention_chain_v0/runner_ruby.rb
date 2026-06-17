#!/usr/bin/env ruby
# Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE in this directory.
# Retention Chain v0 vector runner -- Ruby / json-canonicalization 1.0.0
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
  ref   = "sha256:" + Digest::SHA256.hexdigest(bytes)
  [b64, ref]
end

data = JSON.parse(File.read(ARGV[0], encoding: "utf-8"))
pass = 0
fail = 0

data["vectors"].each do |v|
  b64, ref = sha256_jcs(v["preimage"])
  b64_ok = b64 == v["expected_jcs_bytes_b64"]
  ref_ok = ref == v["expected_chain_ref"]
  if b64_ok && ref_ok
    pass += 1
  else
    fail += 1
    puts "  FAIL #{v['vector_id']} jcs_bytes_b64 mismatch" unless b64_ok
    puts "  FAIL #{v['vector_id']} chain_ref (got #{ref})" unless ref_ok
  end
end

puts "#{pass}/#{pass + fail} PASS"
exit(fail == 0 ? 0 : 1)
