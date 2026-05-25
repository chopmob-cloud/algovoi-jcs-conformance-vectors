// Generic vector-set runner (.NET 9 / Baqhub.Packages.JsonCanonicalization 1.0.1).
//
// Build & run:
//   cd runner_dotnet
//   dotnet run -c Release --quiet -- <vector_set_json>

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Baqhub.Packages.JsonCanonicalization;

if (args.Length < 1)
{
    Console.Error.WriteLine("usage: runner_dotnet <vector_set_json>");
    Environment.Exit(2);
}

var raw = File.ReadAllText(args[0]);
using var doc = JsonDocument.Parse(raw);
var vectors = doc.RootElement.GetProperty("vectors");

int pass = 0, fail = 0;

foreach (var v in vectors.EnumerateArray())
{
    JsonElement payload;
    if (v.TryGetProperty("receipt", out payload)) { }
    else if (v.TryGetProperty("response", out payload)) { }
    else if (v.TryGetProperty("row", out payload)) { }
    else continue;

    var payloadJson = payload.GetRawText();
    var canon = new JsonCanonicalizer(payloadJson).Canonicalize();
    var canonBytes = Encoding.UTF8.GetBytes(canon);
    var b64 = Convert.ToBase64String(canonBytes);
    var digestBytes = SHA256.HashData(canonBytes);
    var digest = Convert.ToHexStringLower(digestBytes);

    var expectedHash = v.TryGetProperty("expected_content_hash", out var ech)
        ? ech.GetString() ?? ""
        : v.TryGetProperty("expected_row_content_hash", out var erch)
            ? erch.GetString() ?? ""
            : "";
    var expectedB64 = v.GetProperty("expected_jcs_bytes_b64").GetString() ?? "";

    if (b64 == expectedB64 && digest == expectedHash)
    {
        pass++;
    }
    else
    {
        fail++;
        Console.WriteLine($"  FAIL {v.GetProperty("vector_id").GetString()}");
    }
}

Console.WriteLine($"{pass}/{pass + fail} PASS");
if (fail > 0) Environment.Exit(1);
