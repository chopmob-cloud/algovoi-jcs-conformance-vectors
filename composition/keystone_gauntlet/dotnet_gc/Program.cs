// Keystone L3 gauntlet -- guard_context, .NET 9 (Baqhub JCS).
// Usage: dotnet run -c Release -- <keystone_guard_context_v1.json>
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Baqhub.Packages.JsonCanonicalization;

var refRe = new Regex("^sha256:[0-9a-f]{64}$");

bool IsRef(JsonNode? v) => v is JsonValue jv && jv.TryGetValue<string>(out var s) && s is not null && refRe.IsMatch(s);

string Gcr(JsonNode src)
{
    var tsNode = src["guard_timestamp_ms"];
    if (tsNode is not JsonValue tv || !tv.TryGetValue<long>(out var ts) || ts < 0)
        throw new Exception("guard_timestamp_ms must be non-negative integer");
    var o = new JsonObject
    {
        ["canon_version"] = "jcs-rfc8785-v1",
        ["type"] = "guard_context",
        ["guard_timestamp_ms"] = ts,
    };
    foreach (var k in new[] { "policy_ref", "mandate_ref", "passport_credential_ref" })
    {
        var val = src[k];
        if (!IsRef(val)) throw new Exception($"{k} must be sha256: ref");
        o[k] = val!.GetValue<string>();
    }
    var canon = new JsonCanonicalizer(o.ToJsonString()).Canonicalize();
    return "sha256:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canon)));
}

var d = JsonNode.Parse(File.ReadAllText(args[0]))!;
int ok = 0;
var fails = new List<string>();
foreach (var v in d["vectors"]!.AsArray())
{
    try { if (Gcr(v!) == v!["expected_guard_context_ref"]!.GetValue<string>()) ok++; else fails.Add("accept-mismatch"); }
    catch { fails.Add("accept-threw"); }
}
foreach (var n in d["negatives"]!.AsArray())
{
    if (n!["must"]!.GetValue<string>() == "reject")
    {
        try { Gcr(n); fails.Add("invalid ACCEPTED"); } catch { ok++; }
    }
    else
    {
        if (Gcr(n) != n["claimed_guard_context_ref"]!.GetValue<string>()) ok++; else fails.Add("tamper NOT detected");
    }
}
var v0 = d["vectors"]![0]!;
var plus = JsonNode.Parse(v0.ToJsonString())!;
plus["guard_timestamp_ms"] = v0["guard_timestamp_ms"]!.GetValue<long>() + 1;
if (Gcr(v0) != Gcr(plus)) ok++; else fails.Add("moment-distinctness collision");
var flt = JsonNode.Parse(v0.ToJsonString())!;
flt["guard_timestamp_ms"] = 1720000000000.5;
try { Gcr(flt); fails.Add("float-ts accepted"); } catch { ok++; }

int total = d["vectors"]!.AsArray().Count + d["negatives"]!.AsArray().Count + 2;
foreach (var f in fails) Console.WriteLine("  FAIL " + f);
Console.WriteLine($"KEYSTONE-GAUNTLET-GC dotnet {ok}/{total}");
Environment.Exit(ok == total && fails.Count == 0 ? 0 : 1);
