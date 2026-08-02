// settlement_round validity gauntlet -- .NET impl.
using System.Text.Json.Nodes;
bool RpiOk(JsonNode? v){ if(v is not JsonValue jv) return false; if(jv.TryGetValue<bool>(out _)) return false; return jv.TryGetValue<long>(out var n) && n>0; }
var d=JsonNode.Parse(File.ReadAllText(args[0]))!;
int ok=0; var fails=new List<string>();
foreach(var r in d["settlement_round_reject_vectors"]!.AsArray()){
  if(!RpiOk(r!["receipt"]!["settlement_round"])) ok++; else fails.Add("bad round ACCEPTED");
}
JsonNode? acc=null;
foreach(var v in d["vectors"]!.AsArray()){ var sr=v!["receipt"]?["settlement_round"]; if(sr is JsonValue jv2 && jv2.TryGetValue<long>(out _)){ acc=v; break; } }
if(RpiOk(acc!["receipt"]!["settlement_round"])) ok++; else fails.Add("valid round REJECTED");
int total=d["settlement_round_reject_vectors"]!.AsArray().Count+1;
foreach(var f in fails) Console.WriteLine("  FAIL "+f);
Console.WriteLine($"SETTLEMENT-ROUND-GAUNTLET dotnet {ok}/{total}");
Environment.Exit(ok==total&&fails.Count==0?0:1);
