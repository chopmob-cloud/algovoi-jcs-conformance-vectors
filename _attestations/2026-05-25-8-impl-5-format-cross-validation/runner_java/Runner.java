// Generic vector-set runner (Java 17 / cyberphone/java-json-canonicalization 1.1).
//
// Build & run:
//   cd runner_java
//   javac -cp "libs/*" Runner.java
//   java -cp ".;libs/*" Runner <vector_set_json>          (Windows)
//   java -cp ".:libs/*" Runner <vector_set_json>          (Unix)

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Base64;

import org.erdtman.jcs.JsonCanonicalizer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Runner {
    public static void main(String[] args) throws Exception {
        String path = args[0];
        ObjectMapper om = new ObjectMapper();
        JsonNode data = om.readTree(new java.io.File(path));
        JsonNode vectors = data.get("vectors");

        int pass = 0, fail = 0;

        for (JsonNode v : vectors) {
            JsonNode payload = v.has("receipt") ? v.get("receipt")
                : v.has("response") ? v.get("response")
                : v.has("row") ? v.get("row")
                : null;
            if (payload == null) continue;

            String payloadJson = om.writeValueAsString(payload);
            JsonCanonicalizer jc = new JsonCanonicalizer(payloadJson);
            byte[] canonBytes = jc.getEncodedUTF8();
            String b64 = Base64.getEncoder().encodeToString(canonBytes);
            byte[] digestBytes = MessageDigest.getInstance("SHA-256").digest(canonBytes);
            StringBuilder digest = new StringBuilder();
            for (byte b : digestBytes) digest.append(String.format("%02x", b));

            String expectedHash = v.has("expected_content_hash")
                ? v.get("expected_content_hash").asText()
                : v.has("expected_row_content_hash")
                ? v.get("expected_row_content_hash").asText()
                : "";
            String expectedB64 = v.get("expected_jcs_bytes_b64").asText();

            if (b64.equals(expectedB64) && digest.toString().equals(expectedHash)) {
                pass++;
            } else {
                fail++;
                System.out.println("  FAIL " + v.get("vector_id").asText());
            }
        }
        System.out.println(pass + "/" + (pass + fail) + " PASS");
        if (fail > 0) System.exit(1);
    }
}
