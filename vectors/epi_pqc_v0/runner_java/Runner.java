// epi_pqc_v0 runner -- Java 17 / cyberphone/java-json-canonicalization 1.1
//
// JCS canonicalisation check only: sha256(JCS(input)) == frame_id
// Falcon-1024 signature + key-lineage checks: Python runner only.
//
// Build & run (from epi_pqc_v0/runner_java/):
//   javac -cp "libs/*" Runner.java
//   java -cp ".;libs/*" Runner "../epi_pqc_v0.json"  (Windows)
//   java -cp ".:libs/*" Runner "../epi_pqc_v0.json"  (Unix)

import java.io.File;
import java.security.MessageDigest;
import java.util.Base64;

import org.erdtman.jcs.JsonCanonicalizer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Runner {

    static String[] sha256Jcs(ObjectMapper om, JsonNode node) throws Exception {
        String json  = om.writeValueAsString(node);
        JsonCanonicalizer jc = new JsonCanonicalizer(json);
        byte[] canonBytes = jc.getEncodedUTF8();
        String b64 = Base64.getEncoder().encodeToString(canonBytes);
        byte[] digestBytes = MessageDigest.getInstance("SHA-256").digest(canonBytes);
        StringBuilder sb = new StringBuilder("sha256:");
        for (byte b : digestBytes) sb.append(String.format("%02x", b));
        return new String[]{b64, sb.toString()};
    }

    public static void main(String[] args) throws Exception {
        String path = args.length > 0 ? args[0] : "epi_pqc_v0.json";
        ObjectMapper om = new ObjectMapper();
        JsonNode data = om.readTree(new File(path));
        JsonNode vectors = data.get("vectors");

        int pass = 0, fail = 0;

        for (JsonNode v : vectors) {
            String[] p  = sha256Jcs(om, v.get("input"));
            String vid   = v.get("id").asText();
            boolean b64Ok = p[0].equals(v.get("expected_jcs_bytes_b64").asText());
            boolean refOk = p[1].equals(v.get("frame_id").asText());

            if (b64Ok && refOk) {
                pass++;
            } else {
                fail++;
                if (!b64Ok) System.out.println("  FAIL " + vid + " jcs_bytes_b64 mismatch");
                if (!refOk) System.out.println("  FAIL " + vid + " frame_id (got " + p[1] + ")");
            }
        }
        System.out.println(pass + "/" + (pass + fail) + " PASS (JCS only)");
        if (fail > 0) System.exit(1);
    }
}
