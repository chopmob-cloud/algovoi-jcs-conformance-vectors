#!/usr/bin/env ruby
# Adversarial gauntlet runner -- Ruby (independent reimplementation, no algovoi import).
# Same three checks; must accept the control and reject all 11 mutations.
# Usage: ruby gauntlet_ruby.rb /path/to/adversarial_isolation_v1.json
require 'json'
require 'digest'

def hex64?(s)
  s.is_a?(String) && s.match?(/\A[0-9a-f]{64}\z/)
end

def uint?(x)
  x.is_a?(Integer) && x >= 0 # true/false are not Integer in Ruby
end

def nonempty_str?(x)
  x.is_a?(String) && !x.empty?
end

def jcs_flat(o)
  # sorted-key compact JSON; byte-identical to RFC 8785 JCS for ASCII/int payloads.
  '{' + o.keys.sort.map { |k| k.to_s.to_json + ':' + o[k].to_json }.join(',') + '}'
end

def check_transition_preimage(o)
  return false unless o.is_a?(Hash)
  return false unless hex64?(o['action_ref'])
  return false unless nonempty_str?(o['state'])
  %w[transition_timestamp_ms authority_verified_at_ms revocation_check_at_ms].each do |k|
    return false unless uint?(o[k])
  end
  true
end

def check_action_ref(o)
  return false unless o.is_a?(Hash)
  %w[agent_id action_type scope].each { |k| return false unless nonempty_str?(o[k]) }
  uint?(o['timestamp_ms'])
end

def check_audit_chain(rows)
  return false unless rows.is_a?(Array) && !rows.empty?
  prev = nil
  rows.each_with_index do |r, i|
    return false unless r.is_a?(Hash)
    return false unless r['chain_position'] == i
    if i.zero?
      return false unless r['prev_hash'].nil?
    else
      return false unless r['prev_hash'] == prev
    end
    recomputed = Digest::SHA256.hexdigest(jcs_flat(r['payload']))
    return false unless recomputed == r['content_hash']
    prev = r['content_hash']
  end
  true
end

CHECKS = {
  'transition_preimage' => method(:check_transition_preimage),
  'action_ref' => method(:check_action_ref),
  'audit_chain' => method(:check_audit_chain)
}.freeze

data = JSON.parse(File.read(ARGV[0], encoding: 'UTF-8'))
ok = 0
total = 0
data['vectors'].each do |v|
  total += 1
  verdict = CHECKS[v['check']].call(v['input']) ? 'accept' : 'reject'
  expected = v['expectation'] == 'reject' ? 'reject' : 'accept'
  good = verdict == expected
  ok += 1 if good
  puts "#{v['vector_id']} #{verdict} expect=#{expected} #{good ? 'OK' : 'MISMATCH'}"
end
puts "GAUNTLET ruby #{ok}/#{total}"
exit(ok == total ? 0 : 1)
