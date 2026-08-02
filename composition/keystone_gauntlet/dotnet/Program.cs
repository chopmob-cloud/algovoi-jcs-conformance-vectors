// Keystone L3 fail-closed gauntlet -- .NET 9 / Baqhub.Packages.JsonCanonicalization 1.0.1.
// Independent reimplementation of decision_audit_ref (no algovoi import).
// Usage: dotnet run -c Release -- <keystone_decision_audit_v1.json>
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Baqhub.Packages.JsonCanonicalization;

var refRe = new Regex("^sha256:[0-9a-f]{64}$");

bool IsRef(JsonNode? v) => v is JsonValue jv && jv.TryGetValue<string>(out var s) && s is not null && refRe.IsMatch(s);

string Dar(JsonNode src, bool withScreen)
{
    var o = new JsonObject();
    foreach (var k in new[] { "decision_ref", "passport_credential_ref", "mandate_ref", "policy_bound_ref" })
    {
        var val = src[k];
        if (!IsRef(val)) throw new Exception($"{k} must be sha256: ref");
        o[k] = val!.GetValue<string>();
    }
    if (withScreen)
    {
        var sbr = src["screen_binding_ref"];
        if (sbr is not null)
        {
            if (!IsRef(sbr)) throw new Exception("screen_binding_ref must be sha256: ref");
            o["screen_binding_ref"] = sbr.GetValue<string>();
        }
    }
    var canon = new JsonCanonicalizer(o.ToJsonString()).Canonicalize();
    var bytes = Encoding.UTF8.GetBytes(canon);
    return "sha256:" + Convert.ToHexStringLower(SHA256.HashData(bytes));
}

var d = JsonNode.Parse(File.ReadAllText(args[0]))!;
int ok = 0;
var fails = new List<string>();
foreach (var v in d["vectors"]!.AsArray())
{
    try { if (Dar(v!, true) == v!["expected_decision_audit_ref"]!.GetValue<string>()) ok++; else fails.Add("accept-mismatch"); }
    catch { fails.Add("accept-threw"); }
}
foreach (var n in d["negatives"]!.AsArray())
{
    if (n!["must"]!.GetValue<string>() == "reject")
    {
        try { Dar(n, true); fails.Add("invalid ACCEPTED"); } catch { ok++; }
    }
    else
    {
        var got = Dar(n, true);
        if (got != n["claimed_decision_audit_ref"]!.GetValue<string>()) ok++; else fails.Add("tamper NOT detected");
    }
}
var v0 = d["vectors"]![0]!;
if (Dar(v0, true) != Dar(v0, false)) ok++; else fails.Add("screen-distinctness collision");
var bad = JsonNode.Parse(v0.ToJsonString())!;
bad["decision_ref"] = "bad";
try { Dar(bad, true); fails.Add("malformed-ref accepted"); } catch { ok++; }

int total = d["vectors"]!.AsArray().Count + d["negatives"]!.AsArray().Count + 2;
foreach (var f in fails) Console.WriteLine("  FAIL " + f);
Console.WriteLine($"KEYSTONE-GAUNTLET dotnet {ok}/{total}");
Environment.Exit(ok == total && fails.Count == 0 ? 0 : 1);
