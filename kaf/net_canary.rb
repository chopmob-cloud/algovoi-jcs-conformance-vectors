#!/usr/bin/env ruby
# frozen_string_literal: true
# KAF network canary (real program file, never run via ruby -e/eval).
# Exit 0 iff the network is UNREACHABLE (hermetic). Exit 1 otherwise.
require "socket"
require "timeout"
require "resolv"

reachable = []

[["1.1.1.1", 443], ["8.8.8.8", 53]].each do |host, port|
  begin
    Timeout.timeout(2) { TCPSocket.new(host, port).close }
    reachable << "tcp #{host}:#{port}"
  rescue Timeout::Error
    # A timeout is INCONCLUSIVE (e.g. firewall drop), not proof of isolation: fail closed.
    reachable << "tcp #{host}:#{port} (timeout: inconclusive, fail-closed)"
  rescue StandardError
    # genuine no route (ECONNREFUSED/ENETUNREACH) is the desired isolated state
  end
end

begin
  Timeout.timeout(2) { Resolv.getaddress("one.one.one.one") }
  reachable << "dns one.one.one.one"
rescue StandardError
  # unreachable is the desired state
end

if reachable.any?
  puts "NETWORK=REACHABLE #{reachable.join('; ')}"
  exit 1
end
puts "NETWORK=NONE (all probes failed, hermetic)"
exit 0
