// Generic input runner (.NET 9 / Baqhub.Packages.JsonCanonicalization 1.0.1). Claim 1 (input bytes) only.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Baqhub.Packages.JsonCanonicalization;

var raw = File.ReadAllText(args[0]);
using var doc = JsonDocument.Parse(raw);
int p = 0, q = 0;
foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
{
    if (!v.TryGetProperty("input", out var inp) || inp.ValueKind == JsonValueKind.Null) continue;
    var canon = new JsonCanonicalizer(inp.GetRawText()).Canonicalize();
    var bytes = Encoding.UTF8.GetBytes(canon);
    var b64 = Convert.ToBase64String(bytes);
    var dg = Convert.ToHexStringLower(SHA256.HashData(bytes));
    if (b64 == v.GetProperty("input_jcs_bytes_b64").GetString() && dg == v.GetProperty("input_content_sha256").GetString())
        p++;
    else
    {
        q++;
        Console.WriteLine($"  FAIL {v.GetProperty("vector_id").GetString()}");
    }
}
Console.WriteLine($"{p}/{p + q} PASS");
if (q > 0) Environment.Exit(1);
