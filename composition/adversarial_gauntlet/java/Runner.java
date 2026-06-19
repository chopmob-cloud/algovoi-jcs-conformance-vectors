// Adversarial gauntlet runner -- Java (independent reimplementation, no algovoi import).
// Jackson for JSON parsing only. Same three checks; accept the control, reject all 11 mutations.
// Compile: javac -cp "libs/*" Runner.java ; Run: java -cp ".;libs/*" Runner <vectors.json>
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

public class Runner {
    static final ObjectMapper M = new ObjectMapper();

    static boolean isHex64(JsonNode n) {
        return n != null && n.isTextual() && n.asText().matches("[0-9a-f]{64}");
    }

    static boolean isUint(JsonNode n) {
        return n != null && n.isIntegralNumber() && n.canConvertToLong() && n.asLong() >= 0;
    }

    static boolean nestr(JsonNode n) {
        return n != null && n.isTextual() && !n.asText().isEmpty();
    }

    static String sha(String s) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes("UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // sorted-key compact JSON; byte-identical to RFC 8785 JCS for ASCII/int payloads.
    static String jcsFlat(JsonNode payload) throws Exception {
        TreeMap<String, String> m = new TreeMap<>();
        Iterator<Map.Entry<String, JsonNode>> it = payload.fields();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> e = it.next();
            m.put(e.getKey(), e.getValue().toString()); // JsonNode.toString() is valid JSON
        }
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> e : m.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append(M.writeValueAsString(e.getKey())).append(":").append(e.getValue());
        }
        return sb.append("}").toString();
    }

    static boolean checkTransition(JsonNode o) {
        if (o == null || !o.isObject()) return false;
        if (!isHex64(o.get("action_ref")) || !nestr(o.get("state"))) return false;
        for (String k : new String[]{"transition_timestamp_ms", "authority_verified_at_ms", "revocation_check_at_ms"})
            if (!isUint(o.get(k))) return false;
        return true;
    }

    static boolean checkActionRef(JsonNode o) {
        if (o == null || !o.isObject()) return false;
        for (String k : new String[]{"agent_id", "action_type", "scope"})
            if (!nestr(o.get(k))) return false;
        return isUint(o.get("timestamp_ms"));
    }

    static boolean checkAuditChain(JsonNode rows) throws Exception {
        if (rows == null || !rows.isArray() || rows.size() == 0) return false;
        String prev = null;
        for (int i = 0; i < rows.size(); i++) {
            JsonNode r = rows.get(i);
            if (!r.isObject()) return false;
            JsonNode cp = r.get("chain_position");
            if (cp == null || !cp.isIntegralNumber() || cp.asLong() != i) return false;
            JsonNode ph = r.get("prev_hash");
            if (i == 0) {
                if (ph == null || !ph.isNull()) return false;
            } else {
                if (ph == null || !ph.isTextual() || !ph.asText().equals(prev)) return false;
            }
            String recomputed = sha(jcsFlat(r.get("payload")));
            JsonNode ch = r.get("content_hash");
            if (ch == null || !ch.isTextual() || !ch.asText().equals(recomputed)) return false;
            prev = ch.asText();
        }
        return true;
    }

    public static void main(String[] args) throws Exception {
        JsonNode doc = M.readTree(Files.readAllBytes(Paths.get(args[0])));
        int ok = 0, total = 0;
        for (JsonNode v : doc.get("vectors")) {
            total++;
            String check = v.get("check").asText();
            JsonNode input = v.get("input");
            boolean accepted = check.equals("transition_preimage") ? checkTransition(input)
                    : check.equals("action_ref") ? checkActionRef(input)
                    : checkAuditChain(input);
            String verdict = accepted ? "accept" : "reject";
            String expected = v.get("expectation").asText().equals("reject") ? "reject" : "accept";
            boolean good = verdict.equals(expected);
            if (good) ok++;
            System.out.println(v.get("vector_id").asText() + " " + verdict + " expect=" + expected + " " + (good ? "OK" : "MISMATCH"));
        }
        System.out.println("GAUNTLET java " + ok + "/" + total);
        System.exit(ok == total ? 0 : 1);
    }
}
