// Adversarial gauntlet runner -- .NET / C# (independent reimplementation, no algovoi import).
// Built-in System.Text.Json only. Same three checks; accept the control, reject all 11 mutations.
// Usage: dotnet run -- /path/to/adversarial_isolation_v1.json
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

class Gauntlet
{
    static readonly Regex Hex = new("^[0-9a-f]{64}$");

    static bool IsHex64(JsonElement e) => e.ValueKind == JsonValueKind.String && Hex.IsMatch(e.GetString());

    static bool IsUint(JsonElement e) => e.ValueKind == JsonValueKind.Number && e.TryGetInt64(out long v) && v >= 0;

    static bool Nestr(JsonElement e) => e.ValueKind == JsonValueKind.String && e.GetString().Length > 0;

    // sorted-key compact JSON; byte-identical to RFC 8785 JCS for ASCII/int payloads.
    static string JcsFlat(JsonElement o)
    {
        var sb = new StringBuilder("{");
        var props = o.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal).ToList();
        for (int i = 0; i < props.Count; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append(JsonSerializer.Serialize(props[i].Name)).Append(':').Append(props[i].Value.GetRawText());
        }
        return sb.Append('}').ToString();
    }

    static string Sha(string s)
    {
        using var h = SHA256.Create();
        return Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
    }

    static bool CheckTransition(JsonElement o)
    {
        if (o.ValueKind != JsonValueKind.Object) return false;
        if (!o.TryGetProperty("action_ref", out var ar) || !IsHex64(ar)) return false;
        if (!o.TryGetProperty("state", out var st) || !Nestr(st)) return false;
        foreach (var k in new[] { "transition_timestamp_ms", "authority_verified_at_ms", "revocation_check_at_ms" })
            if (!o.TryGetProperty(k, out var v) || !IsUint(v)) return false;
        return true;
    }

    static bool CheckActionRef(JsonElement o)
    {
        if (o.ValueKind != JsonValueKind.Object) return false;
        foreach (var k in new[] { "agent_id", "action_type", "scope" })
            if (!o.TryGetProperty(k, out var v) || !Nestr(v)) return false;
        return o.TryGetProperty("timestamp_ms", out var t) && IsUint(t);
    }

    static bool CheckAuditChain(JsonElement rows)
    {
        if (rows.ValueKind != JsonValueKind.Array || rows.GetArrayLength() == 0) return false;
        string prev = null;
        int i = 0;
        foreach (var r in rows.EnumerateArray())
        {
            if (r.ValueKind != JsonValueKind.Object) return false;
            if (!r.TryGetProperty("chain_position", out var cp) || cp.ValueKind != JsonValueKind.Number
                || !cp.TryGetInt64(out long ci) || ci != i) return false;
            if (i == 0)
            {
                if (!r.TryGetProperty("prev_hash", out var ph) || ph.ValueKind != JsonValueKind.Null) return false;
            }
            else
            {
                if (!r.TryGetProperty("prev_hash", out var ph) || ph.ValueKind != JsonValueKind.String
                    || ph.GetString() != prev) return false;
            }
            if (!r.TryGetProperty("payload", out var pl)) return false;
            if (!r.TryGetProperty("content_hash", out var ch) || ch.GetString() != Sha(JcsFlat(pl))) return false;
            prev = ch.GetString();
            i++;
        }
        return true;
    }

    static int Main(string[] args)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(args[0]));
        int ok = 0, total = 0;
        foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
        {
            total++;
            string check = v.GetProperty("check").GetString();
            var input = v.GetProperty("input");
            bool accepted = check switch
            {
                "transition_preimage" => CheckTransition(input),
                "action_ref" => CheckActionRef(input),
                "audit_chain" => CheckAuditChain(input),
                _ => false,
            };
            string verdict = accepted ? "accept" : "reject";
            string expected = v.GetProperty("expectation").GetString() == "reject" ? "reject" : "accept";
            bool good = verdict == expected;
            if (good) ok++;
            Console.WriteLine($"{v.GetProperty("vector_id").GetString()} {verdict} expect={expected} {(good ? "OK" : "MISMATCH")}");
        }
        Console.WriteLine($"GAUNTLET dotnet {ok}/{total}");
        return ok == total ? 0 : 1;
    }
}
