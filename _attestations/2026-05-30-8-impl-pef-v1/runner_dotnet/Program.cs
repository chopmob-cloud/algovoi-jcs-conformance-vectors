// PEF v1 vector runner -- .NET 9 / Baqhub.Packages.JsonCanonicalization 1.0.1
//
// Validates sha256(JCS(receipt)) == expected_receipt_hash and
//           sha256(JCS(preimage)) == expected_frame_id
//
// Build & run:
//   cd runner_dotnet
//   dotnet run -c Release --verbosity quiet -- <vector_set_json>

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Baqhub.Packages.JsonCanonicalization;

if (args.Length < 1)
{
    Console.Error.WriteLine("usage: runner_dotnet <vector_set_json>");
    Environment.Exit(2);
}

(string b64, string hash) Sha256Jcs(string rawJson)
{
    var canon      = new JsonCanonicalizer(rawJson).Canonicalize();
    var canonBytes = Encoding.UTF8.GetBytes(canon);
    var b64        = Convert.ToBase64String(canonBytes);
    var digest     = "sha256:" + Convert.ToHexStringLower(SHA256.HashData(canonBytes));
    return (b64, digest);
}

var raw = File.ReadAllText(args[0]);
using var doc = JsonDocument.Parse(raw);
var vectors = doc.RootElement.GetProperty("vectors");

int pass = 0, fail = 0;

foreach (var v in vectors.EnumerateArray())
{
    var receiptJson  = v.GetProperty("receipt").GetRawText();
    var preimageJson = v.GetProperty("preimage").GetRawText();

    var (r_b64, r_hash) = Sha256Jcs(receiptJson);
    var (p_b64, p_hash) = Sha256Jcs(preimageJson);

    bool receiptOk  = r_b64  == v.GetProperty("expected_receipt_jcs_bytes_b64").GetString()
                   && r_hash == v.GetProperty("expected_receipt_hash").GetString();
    bool preimageOk = p_b64  == v.GetProperty("expected_preimage_jcs_bytes_b64").GetString()
                   && p_hash == v.GetProperty("expected_frame_id").GetString();

    if (receiptOk && preimageOk)
    {
        pass++;
    }
    else
    {
        fail++;
        var vid = v.GetProperty("vector_id").GetString();
        if (!receiptOk)  Console.WriteLine($"  FAIL {vid} receipt_hash");
        if (!preimageOk) Console.WriteLine($"  FAIL {vid} frame_id (got {p_hash})");
    }
}

Console.WriteLine($"{pass}/{pass + fail} PASS");
if (fail > 0) Environment.Exit(1);
