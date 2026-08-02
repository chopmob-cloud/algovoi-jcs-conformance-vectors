// Differential adversarial substrate -- Java 17 canon probe (erdtman JCS 1.1).
// Contract: see probe_python.py. Emits "<id>\t h:<hex> | R:<reason>" per case.
// JsonCanonicalizer(rawString) parses AND canonicalizes -- idiomatic Java usage.
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.erdtman.jcs.JsonCanonicalizer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Probe {
    static final ObjectMapper OM = new ObjectMapper();

    static String verdict(String raw) {
        try {
            byte[] canon = new JsonCanonicalizer(raw).getEncodedUTF8();
            byte[] dig = MessageDigest.getInstance("SHA-256").digest(canon);
            StringBuilder sb = new StringBuilder("h:");
            for (byte b : dig) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "R:err";
        }
    }

    public static void main(String[] args) throws Exception {
        JsonNode d = OM.readTree(new java.io.File(args[0]));
        StringBuilder out = new StringBuilder();
        for (JsonNode c : d.get("cases")) {
            out.append(c.get("id").asText()).append('\t').append(verdict(c.get("raw").asText())).append('\n');
        }
        System.out.print(out);
    }
}
