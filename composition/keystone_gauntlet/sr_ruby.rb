# settlement_round validity gauntlet -- Ruby impl.
require "json"
def rpi(v); raise "bool" if v==true||v==false; raise "not int" unless v.is_a?(Integer); raise "not positive" if v<=0; v; end
d=JSON.parse(File.read(ARGV[0],encoding:"utf-8")); ok=0; fails=[]
d["settlement_round_reject_vectors"].each do |r|
  begin; rpi(r["receipt"]["settlement_round"]); fails<<"#{r['vector_id']}: bad round ACCEPTED"; rescue StandardError; ok+=1; end
end
acc=d["vectors"].find{|v| v.dig("receipt","settlement_round").is_a?(Integer)}
begin; rpi(acc["receipt"]["settlement_round"]); ok+=1; rescue StandardError; fails<<"#{acc['vector_id']}: valid round REJECTED"; end
total=d["settlement_round_reject_vectors"].size+1
fails.each{|f| puts "  FAIL #{f}"}
puts "SETTLEMENT-ROUND-GAUNTLET ruby #{ok}/#{total}"
exit(ok==total && fails.empty? ? 0 : 1)
