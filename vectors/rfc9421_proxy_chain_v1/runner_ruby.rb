#!/usr/bin/env ruby
# runner_ruby.rb -- RFC 9421 §2.5-CONFORMANT cross-validation runner for the
# rfc9421_proxy_chain_v1 fixture. Independent reimplementation (no AlgoVoi
# package): rebuilds the conformant signing base from scratch and verifies.
#
# Conformant vs v0: @method case-preserved, `created` is a parameter (not a
# covered component), and a trailing "@signature-params" line is appended.
#
# Setup: gem install ed25519
# Run:   ruby runner_ruby.rb   (from the dir containing request.fixture.json)

require "json"
require "digest"
require "base64"
require "ed25519"

fix = JSON.parse(File.read("request.fixture.json"))

method = fix["request"]["method"]                 # PRESERVE case (RFC 9421)
path = fix["request"]["path"]
authority = fix["request"]["authority"].downcase
cd_header = fix["request"]["headers"]["content-digest"]
si_header = fix["request"]["headers"]["signature-input"]
sig_header = fix["request"]["headers"]["signature"]
expected_base = fix["signing"]["signing_base"]
pub_hex = fix["keypair"]["public_key_hex"]

# Post-label portion of Signature-Input: everything after the first '='.
params_raw = si_header[(si_header.index("=") + 1)..]
# Covered components = the inner list (quoted names) only.
inner = params_raw[1...params_raw.index(")")]
covered = inner.scan(/"([^"]+)"/).flatten

lines = covered.map do |name|
  val = case name
        when "@method" then method
        when "@authority" then authority
        when "@path" then path
        when "content-digest" then cd_header
        else raise "unexpected covered component for conformant set: #{name}"
        end
  %Q("#{name}": #{val})
end
# RFC 9421 §2.5: trailing @signature-params line carries the post-label value.
lines << %Q("@signature-params": #{params_raw})
signing_base = lines.join("\n")

if signing_base != expected_base
  puts "[FAIL] signing base mismatch"
  puts "  expected: #{expected_base.inspect}"
  puts "  got:      #{signing_base.inspect}"
  exit 1
end
puts "[OK] signing base byte-identical to fixture (rfc9421 conformant)"

expected_cd = "sha-256=:#{Base64.strict_encode64(Digest::SHA256.digest(''))}:"
if expected_cd != cd_header
  puts "[FAIL] content-digest mismatch"
  exit 1
end
puts "[OK] RFC 9530 content-digest verified"

body = sig_header[(sig_header.index("=:") + 2)..].delete_suffix(":")
sig_bytes = Base64.decode64(body)
verify_key = Ed25519::VerifyKey.new([pub_hex].pack("H*"))
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
puts "PASS (Ruby: inline conformant base + ed25519 gem)"
