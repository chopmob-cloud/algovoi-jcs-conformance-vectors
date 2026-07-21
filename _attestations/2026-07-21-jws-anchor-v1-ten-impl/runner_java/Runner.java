// Generic preimage runner -- Java 17 / cyberphone java-json-canonicalization 1.1
import java.security.MessageDigest;
import java.util.Base64;
import org.erdtman.jcs.JsonCanonicalizer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Runner {
    static String[] sha256Jcs(ObjectMapper om, JsonNode node) throws Exception {
        String json = om.writeValueAsString(node);
        byte[] canon = new JsonCanonicalizer(json).getEncodedUTF8();
        String b64 = Base64.getEncoder().encodeToString(canon);
        byte[] d = MessageDigest.getInstance("SHA-256").digest(canon);
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02x", b));
        return new String[]{b64, sb.toString()};
    }
    public static void main(String[] args) throws Exception {
        ObjectMapper om = new ObjectMapper();
        JsonNode data = om.readTree(new java.io.File(args[0]));
        int pass = 0, fail = 0;
        for (JsonNode v : data.get("vectors")) {
            if (v.get("preimage") == null || v.get("preimage").isNull()) continue;
            String[] p = sha256Jcs(om, v.get("preimage"));
            JsonNode ehNode = v.has("expected_content_sha256") ? v.get("expected_content_sha256")
                : v.has("expected_transition_hash") ? v.get("expected_transition_hash") : v.get("expected_action_ref");
            String eh = ehNode.asText();
            boolean ok = p[0].equals(v.get("expected_jcs_bytes_b64").asText()) && p[1].equals(eh);
            if (ok) pass++; else { fail++; System.out.println("  FAIL " + v.get("vector_id").asText()); }
        }
        System.out.println(pass + "/" + (pass + fail) + " PASS");
        if (fail > 0) System.exit(1);
    }
}
