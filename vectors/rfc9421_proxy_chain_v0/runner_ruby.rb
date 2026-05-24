#!/usr/bin/env ruby
# runner_ruby.rb -- RFC 9421 + RFC 9530 cross-validation runner for the
# rfc9421_proxy_chain_v0 fixture.
#
# Uses Ruby ed25519 gem + digest/sha256 + json + base64 stdlib.
#
# Setup (one-off):
#   gem install ed25519
#
# Run from the directory containing request.fixture.json:
#   ruby runner_ruby.rb

require "json"
require "digest"
require "base64"
require "ed25519"

fix = JSON.parse(File.read("request.fixture.json"))

method = fix["request"]["method"].downcase
path = fix["request"]["path"]
authority = fix["request"]["authority"].downcase
cd_header = fix["request"]["headers"]["content-digest"]
si_header = fix["request"]["headers"]["signature-input"]
sig_header = fix["request"]["headers"]["signature"]
expected_base = fix["signing"]["signing_base"]
pub_hex = fix["keypair"]["public_key_hex"]

def parse_signature_input(value)
  eq_paren = value.index("=(")
  body = (eq_paren && eq_paren > 0) ? value[(eq_paren + 1)..] : value
  close = body.index(")")
  inside = body[1...close]
  params = body[(close + 1)..]
  params = params[1..] if params.start_with?(";")

  covered = inside.scan(/"([^"]+)"/).flatten

  param_map = {}
  params.split(";").each do |kv|
    kv = kv.strip
    next if kv.empty?
    eq = kv.index("=")
    next unless eq
    k = kv[0...eq]
    v = kv[(eq + 1)..].delete_prefix('"').delete_suffix('"')
    param_map[k] = v
  end
  [covered, param_map]
end

def parse_signature_value(value)
  eq_colon = value.index("=:")
  body = eq_colon ? value[(eq_colon + 2)..] : value.delete_prefix(":")
  body = body.delete_suffix(":")
  Base64.decode64(body)
end

covered, params = parse_signature_input(si_header)

lines = covered.map do |name|
  val = case name
        when "@method" then method
        when "@authority" then authority
        when "@path" then path
        when "content-digest" then cd_header
        when "created" then params["created"]
        else raise "unknown component: #{name}"
        end
  %Q("#{name}": #{val})
end
signing_base = lines.join("\n")

if signing_base != expected_base
  puts "[FAIL] signing base mismatch"
  puts "  expected: #{expected_base.inspect}"
  puts "  got:      #{signing_base.inspect}"
  exit 1
end
puts "[OK] signing base byte-identical to fixture"

digest = Digest::SHA256.digest("")
expected_cd = "sha-256=:#{Base64.strict_encode64(digest)}:"
if expected_cd != cd_header
  puts "[FAIL] content-digest mismatch"
  exit 1
end
puts "[OK] RFC 9530 content-digest verified"

pub_bytes = [pub_hex].pack("H*")
sig_bytes = parse_signature_value(sig_header)
verify_key = Ed25519::VerifyKey.new(pub_bytes)

begin
  unless verify_key.verify(sig_bytes, signing_base)
    puts "[FAIL] Ed25519 verify failed"
    exit 1
  end
rescue Ed25519::VerifyError
  puts "[FAIL] Ed25519 verify raised VerifyError"
  exit 1
end
puts "[OK] Ed25519 signature verified"
puts "PASS (Ruby: ed25519 gem + Digest::SHA256 stdlib)"
