// Generic preimage runner -- .NET 9 / Baqhub.Packages.JsonCanonicalization 1.0.1
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Baqhub.Packages.JsonCanonicalization;

(string b64, string hash) Sha256Jcs(string rawJson) {
    var canon = new JsonCanonicalizer(rawJson).Canonicalize();
    var bytes = Encoding.UTF8.GetBytes(canon);
    return (Convert.ToBase64String(bytes), Convert.ToHexStringLower(SHA256.HashData(bytes)));
}
var raw = File.ReadAllText(args[0]);
using var doc = JsonDocument.Parse(raw);
int pass = 0, fail = 0;
foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray()) {
    if (!v.TryGetProperty("preimage", out var pre) || pre.ValueKind == JsonValueKind.Null) continue;
    var (b64, hash) = Sha256Jcs(pre.GetRawText());
    string eh = v.TryGetProperty("expected_content_sha256", out var cs) ? cs.GetString()!
        : v.TryGetProperty("expected_transition_hash", out var th) ? th.GetString()! : v.GetProperty("expected_action_ref").GetString()!;
    bool ok = b64 == v.GetProperty("expected_jcs_bytes_b64").GetString() && hash == eh;
    if (ok) pass++; else { fail++; Console.WriteLine($"  FAIL {v.GetProperty("vector_id").GetString()}"); }
}
Console.WriteLine($"{pass}/{pass + fail} PASS");
if (fail > 0) Environment.Exit(1);
