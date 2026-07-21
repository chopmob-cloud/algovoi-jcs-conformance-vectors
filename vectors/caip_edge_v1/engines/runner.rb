# Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0.
# caip_edge_v1 Ruby runner. Correct = \A..\z (absolute anchors). Naive = ^..$: in Ruby ^ and $
# are line anchors (always multiline-style), so $ matches before a trailing newline and ^..$
# SHARES the anchor trap, like Python. The correct Ruby idiom is always \A..\z.
CHAIN = '[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}'.freeze

def body(k)
  return CHAIN if k == 'caip2'
  return CHAIN + ':[-.%a-zA-Z0-9]{1,128}' if k == 'caip10'
  CHAIN + '/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}(/[-.%a-zA-Z0-9]{1,78})?'
end

n = 0
pass = 0
trap = 0
File.foreach('corpus.tsv', chomp: true) do |ln|
  p = ln.split("\t", 3)
  next if p.size < 3

  exp, kind, h = p
  s = [h].pack('H*').force_encoding('UTF-8')
  want = exp == 'accept'
  ok = !(s =~ /\A#{body(kind)}\z/).nil?
  pass += 1 if ok == want
  n += 1
  trap += 1 if exp == 'reject' && !(s =~ /^#{body(kind)}$/).nil?
end
puts "Ruby(Onigmo) correct #{pass}/#{n} | naive ^..$ over-accepts #{trap} reject-vectors"
exit(pass == n ? 0 : 1)
