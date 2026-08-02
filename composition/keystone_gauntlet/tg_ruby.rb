# trust_gate deny-table gauntlet -- Ruby impl.
require "json"
DENY = { "block_untrusted" => ["UNTRUSTED"], "require_trusted" => ["UNTRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE"] }
def blocks(mode, verdict); return false if mode.nil? || mode == "off"; (DENY[mode] || []).include?(verdict); end
d = JSON.parse(File.read(ARGV[0], encoding: "utf-8")); ok = 0; fails = []
d["vectors"].each { |v| blocks(v["mode"], v["verdict"]) == v["expected_blocks"] ? ok += 1 : fails << "#{v['id']}: mismatch" }
fails.each { |f| puts "  FAIL #{f}" }
puts "TRUST-GATE-GAUNTLET ruby #{ok}/#{d['vectors'].size}"
exit(ok == d["vectors"].size && fails.empty? ? 0 : 1)
