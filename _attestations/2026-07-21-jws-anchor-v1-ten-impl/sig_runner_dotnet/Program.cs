// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE at the repo root.
//
// jws_anchor_v1 signature + anchor runner (.NET 9 / BouncyCastle Ed25519).
// .NET has no native Ed25519, so BouncyCastle supplies the primitive; the anchoring
// rule itself is plain SHA-256 over the raw signed bytes.
// Asserts, for every signed vector: the compact JWS verifies under the RFC 8032
// section 7.1 key, and the anchor is sha256 of the RAW SIGNED BYTES.
// Usage: dotnet run -c Release -- <jws_anchor_v1.json>

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

internal static class Program
{
    private static int _pass, _fail;

    private static void Check(string id, string what, bool ok)
    {
        if (ok) _pass++;
        else { _fail++; Console.WriteLine($"  FAIL {id} ({what})"); }
    }

    private static byte[] B64UrlDecode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        var pad = s.Length % 4;
        if (pad != 0) s += new string('=', 4 - pad);
        return Convert.FromBase64String(s);
    }

    private static string Strip(string h)
    {
        var i = h.IndexOf(':');
        return i < 0 ? h : h[(i + 1)..];
    }

    private static string Text(JsonElement v, string name) =>
        v.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

    private static int Main(string[] args)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(args[0]));
        var root = doc.RootElement;
        var pubHex = root.GetProperty("signing_key").GetProperty("public_key_hex").GetString();
        var pubBytes = Convert.FromHexString(pubHex!);
        var pub = new Ed25519PublicKeyParameters(pubBytes, 0);

        foreach (var v in root.GetProperty("vectors").EnumerateArray())
        {
            if (Text(v, "anchor_rule") != "signed_bytes") continue;
            var token = Text(v, "input") ?? Text(v, "issuer_jwt") ?? Text(v, "presentation");
            if (token is null) continue;              // recanon-negative carries no token
            var id = Text(v, "vector_id") ?? "?";
            var jwt = token.Split('~')[0];

            var parts = jwt.Split('.');
            if (parts.Length != 3) { Check(id, "not a compact JWS", false); continue; }

            var verifier = new Ed25519Signer();
            verifier.Init(false, pub);
            var signingInput = Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);
            verifier.BlockUpdate(signingInput, 0, signingInput.Length);
            Check(id, "ed25519 verify", verifier.VerifySignature(B64UrlDecode(parts[2])));

            var want = Text(v, "expected_anchor") ?? Text(v, "presentation_hash");
            if (want is not null)
            {
                var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();
                Check(id, "anchor = sha256(raw signed bytes)", digest == Strip(want));
            }
        }

        Console.WriteLine($"{_pass}/{_pass + _fail} PASS");
        return _fail > 0 ? 1 : 0;
    }
}
