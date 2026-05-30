// PEF v1 vector runner -- Java 17 / cyberphone/java-json-canonicalization 1.1
//
// Validates sha256(JCS(receipt)) == expected_receipt_hash and
//           sha256(JCS(preimage)) == expected_frame_id
//
// Build & run:
//   cd runner_java
//   javac -cp "libs/*" Runner.java
//   java -cp ".;libs/*" Runner <vector_set_json>          (Windows)
//   java -cp ".:libs/*" Runner <vector_set_json>          (Unix)

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.erdtman.jcs.JsonCanonicalizer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Runner {

    static String[] sha256Jcs(ObjectMapper om, JsonNode node) throws Exception {
        String json = om.writeValueAsString(node);
        JsonCanonicalizer jc = new JsonCanonicalizer(json);
        byte[] canonBytes = jc.getEncodedUTF8();
        String b64 = Base64.getEncoder().encodeToString(canonBytes);
        byte[] digestBytes = MessageDigest.getInstance("SHA-256").digest(canonBytes);
        StringBuilder sb = new StringBuilder("sha256:");
        for (byte b : digestBytes) sb.append(String.format("%02x", b));
        return new String[]{b64, sb.toString()};
    }

    public static void main(String[] args) throws Exception {
        ObjectMapper om = new ObjectMapper();
        JsonNode data = om.readTree(new java.io.File(args[0]));
        JsonNode vectors = data.get("vectors");

        int pass = 0, fail = 0;

        for (JsonNode v : vectors) {
            String[] r = sha256Jcs(om, v.get("receipt"));
            String[] p = sha256Jcs(om, v.get("preimage"));

            boolean receiptOk  = r[0].equals(v.get("expected_receipt_jcs_bytes_b64").asText())
                              && r[1].equals(v.get("expected_receipt_hash").asText());
            boolean preimageOk = p[0].equals(v.get("expected_preimage_jcs_bytes_b64").asText())
                              && p[1].equals(v.get("expected_frame_id").asText());

            if (receiptOk && preimageOk) {
                pass++;
            } else {
                fail++;
                String vid = v.get("vector_id").asText();
                if (!receiptOk)  System.out.println("  FAIL " + vid + " receipt_hash");
                if (!preimageOk) System.out.println("  FAIL " + vid + " frame_id (got " + p[1] + ")");
            }
        }
        System.out.println(pass + "/" + (pass + fail) + " PASS");
        if (fail > 0) System.exit(1);
    }
}
