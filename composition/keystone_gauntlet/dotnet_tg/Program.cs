// trust_gate deny-table gauntlet -- .NET impl.
using System.Text.Json.Nodes;
string? ModeStr(JsonNode? mode){ if(mode is JsonValue jv && jv.TryGetValue<string>(out var s)) return s; return null; }
bool Blocks(JsonNode? mode, string verdict){
  var m = ModeStr(mode);
  if(string.IsNullOrEmpty(m) || m == "off") return false;
  return m switch {
    "block_untrusted" => verdict == "UNTRUSTED",
    "require_trusted" => verdict is "UNTRUSTED" or "PROVISIONAL" or "INSUFFICIENT_EVIDENCE",
    _ => false
  };
}
var d = JsonNode.Parse(File.ReadAllText(args[0]))!;
int ok = 0; var fails = new List<string>();
foreach(var v in d["vectors"]!.AsArray()){
  var got = Blocks(v!["mode"], v["verdict"]!.GetValue<string>());
  if(got == v["expected_blocks"]!.GetValue<bool>()) ok++; else fails.Add(v["id"]!.GetValue<string>()+": mismatch");
}
int total = d["vectors"]!.AsArray().Count;
foreach(var f in fails) Console.WriteLine("  FAIL "+f);
Console.WriteLine($"TRUST-GATE-GAUNTLET dotnet {ok}/{total}");
Environment.Exit(ok==total && fails.Count==0 ? 0 : 1);
