// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE at the repo root.
//
// jws_anchor_v1 signature + anchor runner (Java 15+ / JDK-native Ed25519, no third-party crypto).
// Asserts, for every signed vector: the compact JWS verifies under the RFC 8032 section 7.1
// key, and the anchor is sha256 of the RAW SIGNED BYTES.
// Usage: java -cp ".:libs/*" SigRunner <jws_anchor_v1.json>

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

public class SigRunner {

    // SubjectPublicKeyInfo prefix for a raw Ed25519 key (RFC 8410): 12 bytes then the 32 key bytes.
    private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");

    static byte[] b64urlDecode(String s) {
        int pad = s.length() % 4;
        if (pad != 0) s = s + "=".repeat(4 - pad);
        return Base64.getUrlDecoder().decode(s);
    }

    static String strip(String h) {
        int i = h.indexOf(':');
        return i < 0 ? h : h.substring(i + 1);
    }

    static int pass = 0, fail = 0;

    static void check(String id, String what, boolean ok) {
        if (ok) pass++;
        else { fail++; System.out.println("  FAIL " + id + " (" + what + ")"); }
    }

    public static void main(String[] args) throws Exception {
        JsonNode d = new ObjectMapper().readTree(new File(args[0]));
        byte[] raw = HexFormat.of().parseHex(d.get("signing_key").get("public_key_hex").asText());
        byte[] spki = new byte[SPKI_PREFIX.length + raw.length];
        System.arraycopy(SPKI_PREFIX, 0, spki, 0, SPKI_PREFIX.length);
        System.arraycopy(raw, 0, spki, SPKI_PREFIX.length, raw.length);
        PublicKey pub = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));

        for (JsonNode v : d.get("vectors")) {
            if (!"signed_bytes".equals(v.path("anchor_rule").asText())) continue;
            String token = v.hasNonNull("input") ? v.get("input").asText()
                    : v.hasNonNull("issuer_jwt") ? v.get("issuer_jwt").asText()
                    : v.hasNonNull("presentation") ? v.get("presentation").asText() : null;
            if (token == null) continue;               // recanon-negative carries no token
            String id = v.get("vector_id").asText();
            String jwt = token.split("~", 2)[0];

            String[] parts = jwt.split("\\.");
            if (parts.length != 3) { check(id, "not a compact JWS", false); continue; }
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(pub);
            sig.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
            check(id, "ed25519 verify", sig.verify(b64urlDecode(parts[2])));

            String want = v.hasNonNull("expected_anchor") ? v.get("expected_anchor").asText()
                    : v.hasNonNull("presentation_hash") ? v.get("presentation_hash").asText() : null;
            if (want != null) {
                byte[] dig = MessageDigest.getInstance("SHA-256")
                        .digest(token.getBytes(StandardCharsets.UTF_8));
                check(id, "anchor = sha256(raw signed bytes)",
                        HexFormat.of().formatHex(dig).equals(strip(want)));
            }
        }
        System.out.println(pass + "/" + (pass + fail) + " PASS");
        if (fail > 0) System.exit(1);
    }
}
