# Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE at the repo root.
#
# jws_anchor_v1 signature + anchor runner (Ruby / OpenSSL raw Ed25519 key).
# Asserts, for every signed vector: the compact JWS verifies under the RFC 8032
# section 7.1 key, and the anchor is sha256 of the RAW SIGNED BYTES.
# Usage: ruby sig_runner_ruby.rb <jws_anchor_v1.json>

require "json"
require "digest"
require "base64"
require "openssl"

def b64url_decode(s)
  pad = s.length % 4
  s += "=" * (4 - pad) unless pad.zero?
  Base64.urlsafe_decode64(s)
end

def strip_prefix(h)
  i = h.index(":")
  i ? h[(i + 1)..] : h
end

path = ARGV[0] or abort("usage: ruby sig_runner_ruby.rb <set.json>")
d = JSON.parse(File.read(path, encoding: "UTF-8"))
pub_raw = [d.dig("signing_key", "public_key_hex")].pack("H*")
pub = OpenSSL::PKey.new_raw_public_key("ED25519", pub_raw)

pass = 0
fail = 0
check = lambda do |id, what, ok|
  if ok then pass += 1 else fail += 1; puts "  FAIL #{id} (#{what})" end
end

d["vectors"].each do |v|
  next unless v["anchor_rule"] == "signed_bytes"
  token = v["input"] || v["issuer_jwt"] || v["presentation"]
  next if token.nil?                       # recanon-negative carries no token
  jwt = token.split("~", 2)[0]

  parts = jwt.split(".")
  if parts.length != 3
    check.call(v["vector_id"], "not a compact JWS", false)
    next
  end
  sig = b64url_decode(parts[2])
  signing_input = "#{parts[0]}.#{parts[1]}"
  check.call(v["vector_id"], "ed25519 verify", pub.verify(nil, sig, signing_input))

  want = v["expected_anchor"] || v["presentation_hash"]
  unless want.nil?
    check.call(v["vector_id"], "anchor = sha256(raw signed bytes)",
               Digest::SHA256.hexdigest(token) == strip_prefix(want))
  end
end

puts "#{pass}/#{pass + fail} PASS"
exit(fail.zero? ? 0 : 1)
