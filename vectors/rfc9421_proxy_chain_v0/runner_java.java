// runner_java.java -- RFC 9421 + RFC 9530 cross-validation runner for the
// rfc9421_proxy_chain_v0 fixture.
//
// Uses JDK 17 stdlib only (java.security Ed25519 + java.security.MessageDigest
// + java.util.Base64). No external JSON parser -- fields are extracted with
// java.util.regex against the well-known fixture structure.
//
// Run from the directory containing request.fixture.json:
//   java runner_java.java
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class runner_java {

    static String findJsonString(String json, String key) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");
        Matcher m = p.matcher(json);
        if (!m.find()) throw new RuntimeException("missing key: " + key);
        // Unescape \" \\ \n
        return m.group(1)
            .replace("\\n", "\n")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");
    }

    static Map<String, String> parseSignatureInput(String value) {
        Map<String, String> out = new LinkedHashMap<>();
        int eqParen = value.indexOf("=(");
        String body = (eqParen > 0) ? value.substring(eqParen + 1) : value;
        int close = body.indexOf(')');
        String inside = body.substring(1, close);
        String params = body.substring(close + 1);
        if (params.startsWith(";")) params = params.substring(1);

        Matcher m = Pattern.compile("\"([^\"]+)\"").matcher(inside);
        StringBuilder coveredCsv = new StringBuilder();
        while (m.find()) {
            if (coveredCsv.length() > 0) coveredCsv.append(",");
            coveredCsv.append(m.group(1));
        }
        out.put("_covered", coveredCsv.toString());

        for (String kv : params.split(";")) {
            kv = kv.trim();
            if (kv.isEmpty()) continue;
            int eq = kv.indexOf('=');
            if (eq > 0) {
                String k = kv.substring(0, eq);
                String v = kv.substring(eq + 1);
                if (v.startsWith("\"") && v.endsWith("\"")) v = v.substring(1, v.length() - 1);
                out.put(k, v);
            }
        }
        return out;
    }

    static byte[] parseSignatureValue(String value) {
        int eqColon = value.indexOf("=:");
        String body = (eqColon > 0) ? value.substring(eqColon + 2) : value.replaceFirst("^:", "");
        if (body.endsWith(":")) body = body.substring(0, body.length() - 1);
        return Base64.getDecoder().decode(body);
    }

    static PublicKey loadEd25519PublicKey(byte[] pubKeyBytes) throws Exception {
        // Ed25519 pubkey: sign bit of x in MSB of last byte; y is little-endian
        boolean xOdd = (pubKeyBytes[31] & 0x80) != 0;
        byte[] yBytes = pubKeyBytes.clone();
        yBytes[31] &= 0x7F;
        // reverse to big-endian for BigInteger
        byte[] yBe = new byte[yBytes.length];
        for (int i = 0; i < yBytes.length; i++) yBe[i] = yBytes[yBytes.length - 1 - i];
        BigInteger y = new BigInteger(1, yBe);
        EdECPoint point = new EdECPoint(xOdd, y);
        NamedParameterSpec spec = new NamedParameterSpec("Ed25519");
        EdECPublicKeySpec keySpec = new EdECPublicKeySpec(spec, point);
        KeyFactory kf = KeyFactory.getInstance("Ed25519");
        return kf.generatePublic(keySpec);
    }

    public static void main(String[] args) throws Exception {
        String json = Files.readString(Path.of("request.fixture.json"));
        String pubHex = findJsonString(json, "public_key_hex");
        String method = findJsonString(json, "method").toLowerCase();
        String path = findJsonString(json, "path");
        String authority = findJsonString(json, "authority").toLowerCase();
        String contentDigestHeader = findJsonString(json, "content-digest");
        String signatureInputHeader = findJsonString(json, "signature-input");
        String signatureHeader = findJsonString(json, "signature");
        String expectedSigningBase = findJsonString(json, "signing_base");

        Map<String, String> si = parseSignatureInput(signatureInputHeader);
        String[] covered = si.get("_covered").split(",");

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < covered.length; i++) {
            String name = covered[i];
            String val;
            switch (name) {
                case "@method": val = method; break;
                case "@authority": val = authority; break;
                case "@path": val = path; break;
                case "content-digest": val = contentDigestHeader; break;
                case "created": val = si.get("created"); break;
                default: throw new RuntimeException("unknown component: " + name);
            }
            if (i > 0) sb.append("\n");
            sb.append("\"").append(name).append("\": ").append(val);
        }
        String signingBase = sb.toString();

        if (!signingBase.equals(expectedSigningBase)) {
            System.out.println("[FAIL] signing base mismatch");
            System.out.println("  expected: " + expectedSigningBase);
            System.out.println("  got:      " + signingBase);
            System.exit(1);
        }
        System.out.println("[OK] signing base byte-identical to fixture");

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(new byte[0]);
        String expectedCd = "sha-256=:" + Base64.getEncoder().encodeToString(digest) + ":";
        if (!expectedCd.equals(contentDigestHeader)) {
            System.out.println("[FAIL] content-digest mismatch");
            System.exit(1);
        }
        System.out.println("[OK] RFC 9530 content-digest verified");

        byte[] pubKeyBytes = HexFormat.of().parseHex(pubHex);
        PublicKey publicKey = loadEd25519PublicKey(pubKeyBytes);
        byte[] sigBytes = parseSignatureValue(signatureHeader);

        Signature sig = Signature.getInstance("Ed25519");
        sig.initVerify(publicKey);
        sig.update(signingBase.getBytes(StandardCharsets.UTF_8));
        if (!sig.verify(sigBytes)) {
            System.out.println("[FAIL] Ed25519 verify failed");
            System.exit(1);
        }
        System.out.println("[OK] Ed25519 signature verified");
        System.out.println("PASS (Java JDK 17 stdlib: java.security Ed25519 + MessageDigest)");
    }
}
