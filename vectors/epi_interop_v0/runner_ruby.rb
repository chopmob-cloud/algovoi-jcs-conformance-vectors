#!/usr/bin/env ruby
# epi_interop_v0 runner -- Ruby / json-canonicalization 1.0.0
#
# Validates sha256(JCS(input)) == frame_id for each vector
#
# Usage (from epi_interop_v0/):  ruby runner_ruby.rb
# Requires: gem install json-canonicalization

require "json"
require "json/canonicalization"
require "digest"
require "base64"

here   = File.dirname(File.expand_path(__FILE__))
data   = JSON.parse(File.read(File.join(here, "epi_interop_v0.json"), encoding: "utf-8"))
pass = 0; fail = 0

data["vectors"].each do |v|
  canon = v["input"].to_json_c14n
  bytes = canon.dup.force_encoding("ASCII-8BIT")
  b64   = Base64.strict_encode64(bytes)
  ref   = "sha256:" + Digest::SHA256.hexdigest(bytes)

  if b64 == v["expected_jcs_bytes_b64"] && ref == v["frame_id"]
    pass += 1
  else
    fail += 1
    puts "  FAIL #{v['id']} jcs_bytes_b64 mismatch" unless b64 == v["expected_jcs_bytes_b64"]
    puts "  FAIL #{v['id']} frame_id (got #{ref})"  unless ref == v["frame_id"]
  end
end

puts "#{pass}/#{pass + fail} PASS"
exit(fail == 0 ? 0 : 1)
