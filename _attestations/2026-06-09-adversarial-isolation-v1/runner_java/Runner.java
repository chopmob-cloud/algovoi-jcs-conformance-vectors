// Generic input runner (Java 17 / cyberphone java-json-canonicalization 1.1). Claim 1 (input bytes) only.
import java.security.MessageDigest;
import java.util.Base64;

import org.erdtman.jcs.JsonCanonicalizer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Runner {
    public static void main(String[] args) throws Exception {
        ObjectMapper om = new ObjectMapper();
        JsonNode data = om.readTree(new java.io.File(args[0]));
        int p = 0, q = 0;
        for (JsonNode v : data.get("vectors")) {
            JsonNode in = v.get("input");
            if (in == null || in.isNull()) continue;
            byte[] canon = new JsonCanonicalizer(om.writeValueAsString(in)).getEncodedUTF8();
            String b64 = Base64.getEncoder().encodeToString(canon);
            byte[] d = MessageDigest.getInstance("SHA-256").digest(canon);
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b));
            if (b64.equals(v.get("input_jcs_bytes_b64").asText())
                    && sb.toString().equals(v.get("input_content_sha256").asText())) {
                p++;
            } else {
                q++;
                System.out.println("  FAIL " + v.get("vector_id").asText());
            }
        }
        System.out.println(p + "/" + (p + q) + " PASS");
        if (q > 0) System.exit(1);
    }
}
