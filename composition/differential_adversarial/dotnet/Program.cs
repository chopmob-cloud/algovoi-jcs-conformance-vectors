// Differential adversarial substrate -- .NET 9 canon probe (Baqhub JCS 1.0.1).
// Contract: see probe_python.py. Emits "<id>\t h:<hex> | R:<reason>" per case.
// JsonCanonicalizer(rawString) parses AND canonicalizes -- idiomatic .NET usage.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Baqhub.Packages.JsonCanonicalization;

string Verdict(string raw)
{
    try
    {
        var canon = new JsonCanonicalizer(raw).Canonicalize();
        var bytes = Encoding.UTF8.GetBytes(canon);
        return "h:" + Convert.ToHexStringLower(SHA256.HashData(bytes));
    }
    catch
    {
        return "R:err";
    }
}

var d = JsonNode.Parse(File.ReadAllText(args[0]))!;
var sb = new StringBuilder();
foreach (var c in d["cases"]!.AsArray())
{
    var id = c!["id"]!.GetValue<string>();
    var raw = c["raw"]!.GetValue<string>();
    sb.Append(id).Append('\t').Append(Verdict(raw)).Append('\n');
}
Console.Write(sb.ToString());
