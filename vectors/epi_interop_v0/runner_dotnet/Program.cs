// epi_interop_v0 runner -- .NET 9 / Baqhub.Packages.JsonCanonicalization 1.0.1
//
// Validates sha256(JCS(input)) == frame_id for each vector
//
// Build & run (from epi_interop_v0/runner_dotnet/):
//   dotnet run -c Release --verbosity quiet

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Baqhub.Packages.JsonCanonicalization;

(string b64, string hash) Sha256Jcs(string rawJson)
{
    var canon      = new JsonCanonicalizer(rawJson).Canonicalize();
    var canonBytes = Encoding.UTF8.GetBytes(canon);
    var b64        = Convert.ToBase64String(canonBytes);
    var digest     = "sha256:" + Convert.ToHexStringLower(SHA256.HashData(canonBytes));
    return (b64, digest);
}

var vecFile = args.Length > 0
    ? args[0]
    : Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "epi_interop_v0.json");
var raw = File.ReadAllText(vecFile);
using var doc = JsonDocument.Parse(raw);
var vectors = doc.RootElement.GetProperty("vectors");

int pass = 0, fail = 0;

foreach (var v in vectors.EnumerateArray())
{
    var inputJson = v.GetProperty("input").GetRawText();
    var (b64, frameId) = Sha256Jcs(inputJson);

    bool b64Ok = b64     == v.GetProperty("expected_jcs_bytes_b64").GetString();
    bool refOk = frameId == v.GetProperty("frame_id").GetString();

    if (b64Ok && refOk)
    {
        pass++;
    }
    else
    {
        fail++;
        var vid = v.GetProperty("id").GetString();
        if (!b64Ok) Console.WriteLine($"  FAIL {vid} jcs_bytes_b64 mismatch");
        if (!refOk) Console.WriteLine($"  FAIL {vid} frame_id (got {frameId})");
    }
}

Console.WriteLine($"{pass}/{pass + fail} PASS");
if (fail > 0) Environment.Exit(1);
