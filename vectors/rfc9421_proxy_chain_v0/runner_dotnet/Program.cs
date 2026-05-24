// runner_dotnet -- RFC 9421 + RFC 9530 cross-validation runner for the
// rfc9421_proxy_chain_v0 fixture.
//
// Uses NSec.Cryptography (libsodium binding) for Ed25519 +
// System.Security.Cryptography.SHA256 + System.Text.Json. Run from the
// parent directory containing request.fixture.json:
//   cd runner_dotnet && dotnet run -c Release

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using NSec.Cryptography;

class Program
{
    static (List<string> covered, Dictionary<string, string> parameters) ParseSignatureInput(string value)
    {
        int eqParen = value.IndexOf("=(", StringComparison.Ordinal);
        string body = eqParen > 0 ? value[(eqParen + 1)..] : value;
        int close = body.IndexOf(')');
        string inside = body.Substring(1, close - 1);
        string parameters = body[(close + 1)..];
        if (parameters.StartsWith(";")) parameters = parameters[1..];

        var covered = new List<string>();
        foreach (Match m in Regex.Matches(inside, "\"([^\"]+)\""))
            covered.Add(m.Groups[1].Value);

        var paramMap = new Dictionary<string, string>();
        foreach (var kv in parameters.Split(';'))
        {
            var t = kv.Trim();
            if (string.IsNullOrEmpty(t)) continue;
            int eq = t.IndexOf('=');
            if (eq > 0)
            {
                var k = t[..eq];
                var v = t[(eq + 1)..].Trim('"');
                paramMap[k] = v;
            }
        }
        return (covered, paramMap);
    }

    static byte[] ParseSignatureValue(string value)
    {
        int eqColon = value.IndexOf("=:", StringComparison.Ordinal);
        string body = eqColon > 0 ? value[(eqColon + 2)..] : value.TrimStart(':');
        body = body.TrimEnd(':');
        return Convert.FromBase64String(body);
    }

    static byte[] HexDecode(string hex)
    {
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    static int Main()
    {
        var json = File.ReadAllText("../request.fixture.json");
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var req = root.GetProperty("request");
        var headers = req.GetProperty("headers");

        string method = req.GetProperty("method").GetString()!.ToLowerInvariant();
        string path = req.GetProperty("path").GetString()!;
        string authority = req.GetProperty("authority").GetString()!.ToLowerInvariant();
        string cdHeader = headers.GetProperty("content-digest").GetString()!;
        string siHeader = headers.GetProperty("signature-input").GetString()!;
        string sigHeader = headers.GetProperty("signature").GetString()!;
        string expectedBase = root.GetProperty("signing").GetProperty("signing_base").GetString()!;
        string pubHex = root.GetProperty("keypair").GetProperty("public_key_hex").GetString()!;

        var (covered, parameters) = ParseSignatureInput(siHeader);

        var lines = new List<string>();
        foreach (var name in covered)
        {
            string val = name switch
            {
                "@method" => method,
                "@authority" => authority,
                "@path" => path,
                "content-digest" => cdHeader,
                "created" => parameters["created"],
                _ => throw new Exception($"unknown component: {name}")
            };
            lines.Add($"\"{name}\": {val}");
        }
        string signingBase = string.Join("\n", lines);

        if (signingBase != expectedBase)
        {
            Console.WriteLine("[FAIL] signing base mismatch");
            Console.WriteLine($"  expected: {expectedBase}");
            Console.WriteLine($"  got:      {signingBase}");
            return 1;
        }
        Console.WriteLine("[OK] signing base byte-identical to fixture");

        var digest = SHA256.HashData(Array.Empty<byte>());
        string expectedCd = "sha-256=:" + Convert.ToBase64String(digest) + ":";
        if (expectedCd != cdHeader)
        {
            Console.WriteLine("[FAIL] content-digest mismatch");
            return 1;
        }
        Console.WriteLine("[OK] RFC 9530 content-digest verified");

        var pubKeyBytes = HexDecode(pubHex);
        var sigBytes = ParseSignatureValue(sigHeader);
        var publicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, pubKeyBytes, KeyBlobFormat.RawPublicKey);
        var msgBytes = Encoding.UTF8.GetBytes(signingBase);

        if (!SignatureAlgorithm.Ed25519.Verify(publicKey, msgBytes, sigBytes))
        {
            Console.WriteLine("[FAIL] Ed25519 verify failed");
            return 1;
        }
        Console.WriteLine("[OK] Ed25519 signature verified");
        Console.WriteLine("PASS (.NET 9: NSec.Cryptography 24.4.0 Ed25519 + SHA256 stdlib)");
        return 0;
    }
}
