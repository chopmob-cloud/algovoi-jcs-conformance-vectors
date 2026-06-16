// Copyright 2026 AlgoVoi. All rights reserved.
// AlgoVoi Commercial Software License -- see LICENSE in this directory.
// Retention Chain v1 vector runner -- .NET 9 / Baqhub.Packages.JsonCanonicalization 1.0.1
//
// Validates sha256(JCS(preimage)) == expected_chain_ref
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
    var preimageJson = v.GetProperty("preimage").GetRawText();
    var (b64, chainRef) = Sha256Jcs(preimageJson);

    bool b64Ok = b64     == v.GetProperty("expected_jcs_bytes_b64").GetString();
    bool refOk = chainRef == v.GetProperty("expected_chain_ref").GetString();

    if (b64Ok && refOk)
    {
        pass++;
    }
    else
    {
        fail++;
        var vid = v.GetProperty("vector_id").GetString();
        if (!b64Ok) Console.WriteLine($"  FAIL {vid} jcs_bytes_b64 mismatch");
        if (!refOk) Console.WriteLine($"  FAIL {vid} chain_ref (got {chainRef})");
    }
}

Console.WriteLine($"{pass}/{pass + fail} PASS");
if (fail > 0) Environment.Exit(1);
