// revocation_ref fail-closed gauntlet -- .NET 9 (Baqhub JCS).
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Baqhub.Packages.JsonCanonicalization;

var refRe = new Regex("^sha256:[0-9a-f]{64}$");
string[] REASONS = { "USER_REQUESTED", "COMPLIANCE_TRIGGERED", "EXPIRED", "KEY_COMPROMISE", "SUPERSEDED", "ADMIN" };
string[] STATUS = { "active", "suspended", "revoked", "inactive" };

bool IsRef(JsonNode? v) => v is JsonValue jv && jv.TryGetValue<string>(out var s) && s is not null && refRe.IsMatch(s);
string Hjcs(JsonNode o) { var canon = new JsonCanonicalizer(o.ToJsonString()).Canonicalize(); return "sha256:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canon))); }

string Rref(JsonNode f)
{
    string Ref(string k) { var v = f[k]; if (!IsRef(v)) throw new Exception(k); return v!.GetValue<string>(); }
    long Int(string k) { var v = f[k]; if (v is not JsonValue jv || !jv.TryGetValue<long>(out var n) || n < 0) throw new Exception(k); return n; }
    string Enm(string k, string[] a) { var v = f[k]; if (v is not JsonValue jv || !jv.TryGetValue<string>(out var s) || Array.IndexOf(a, s) < 0) throw new Exception(k); return s!; }
    string Str(string k) { var v = f[k]; if (v is not JsonValue jv || !jv.TryGetValue<string>(out var s) || string.IsNullOrEmpty(s)) throw new Exception(k); return s!; }
    var o = new JsonObject
    {
        ["canon_version"] = "jcs-rfc8785-v1", ["type"] = "revocation_link", ["subject_ref"] = Ref("subject_ref"),
        ["revoked_at_ms"] = Int("revoked_at_ms"), ["reason_code"] = Enm("reason_code", REASONS), ["issuer_did"] = Str("issuer_did"),
        ["prev_status"] = Enm("prev_status", STATUS), ["new_status"] = Enm("new_status", STATUS), ["seq"] = Int("seq"),
    };
    var p = f["prev_revocation_ref"];
    if (p is null) o["prev_revocation_ref"] = null;
    else { if (!IsRef(p)) throw new Exception("prev"); o["prev_revocation_ref"] = p.GetValue<string>(); }
    return Hjcs(o);
}

bool Vchain(JsonArray links)
{
    string? prev = null; int i = 0;
    foreach (var l in links)
    {
        var sq = l!["seq"]; if (sq is not JsonValue sv || !sv.TryGetValue<long>(out var s) || s != i) return false;
        var pn = l["prev_revocation_ref"]; string? lp = (pn is JsonValue pv && pv.TryGetValue<string>(out var pstr)) ? pstr : null;
        if (lp != prev) return false;
        prev = Hjcs(l); i++;
    }
    return true;
}

var d = JsonNode.Parse(File.ReadAllText(args[0]))!;
int ok = 0; var fails = new List<string>();
foreach (var v in d["vectors"]!.AsArray()) { try { if (Rref(v!) == v!["expected_revocation_ref"]!.GetValue<string>()) ok++; else fails.Add(v!["id"]!.GetValue<string>()); } catch { fails.Add(v!["id"]!.GetValue<string>()); } }
foreach (var n in d["negatives"]!.AsArray()) { try { Rref(n!); fails.Add(n!["id"]!.GetValue<string>()); } catch { ok++; } }
foreach (var t in d["tamper"]!.AsArray()) { if (Rref(t!) != t!["claimed_revocation_ref"]!.GetValue<string>()) ok++; else fails.Add(t!["id"]!.GetValue<string>()); }
foreach (var c in d["chain_valid"]!.AsArray()) { if (Vchain(c!["links"]!.AsArray())) ok++; else fails.Add(c!["id"]!.GetValue<string>()); }
foreach (var c in d["chain_invalid"]!.AsArray()) { if (!Vchain(c!["links"]!.AsArray())) ok++; else fails.Add(c!["id"]!.GetValue<string>()); }
int total = d["vectors"]!.AsArray().Count + d["negatives"]!.AsArray().Count + d["tamper"]!.AsArray().Count + d["chain_valid"]!.AsArray().Count + d["chain_invalid"]!.AsArray().Count;
foreach (var f in fails) Console.WriteLine("  FAIL " + f);
Console.WriteLine($"REVOCATION-GAUNTLET dotnet {ok}/{total}");
Environment.Exit(ok == total && fails.Count == 0 ? 0 : 1);
