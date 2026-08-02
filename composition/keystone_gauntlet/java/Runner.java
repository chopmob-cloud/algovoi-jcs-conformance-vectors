// Keystone L3 fail-closed gauntlet -- Java 17 / cyberphone java-json-canonicalization 1.1.
// Independent reimplementation of decision_audit_ref (no algovoi import).
// Build & run:
//   javac -cp "libs/*" Runner.java
//   java -cp ".;libs/*" Runner <keystone_decision_audit_v1.json>   (Windows)
//   java -cp ".:libs/*" Runner <keystone_decision_audit_v1.json>   (Unix)
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.erdtman.jcs.JsonCanonicalizer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class Runner {
    static final String REF = "^sha256:[0-9a-f]{64}$";
    static final ObjectMapper OM = new ObjectMapper();

    static ObjectNode buildAudit(JsonNode src, boolean withScreen) {
        ObjectNode o = OM.createObjectNode();
        for (String k : new String[]{"decision_ref", "passport_credential_ref", "mandate_ref", "policy_bound_ref"}) {
            JsonNode val = src.get(k);
            if (val == null || !val.isTextual() || !val.asText().matches(REF))
                throw new IllegalArgumentException(k + " must be sha256: ref");
            o.put(k, val.asText());
        }
        JsonNode sbr = src.get("screen_binding_ref");
        if (withScreen && sbr != null && !sbr.isNull()) {
            if (!sbr.isTextual() || !sbr.asText().matches(REF))
                throw new IllegalArgumentException("screen_binding_ref must be sha256: ref");
            o.put("screen_binding_ref", sbr.asText());
        }
        return o;
    }

    static String dar(JsonNode src, boolean withScreen) throws Exception {
        String json = OM.writeValueAsString(buildAudit(src, withScreen));
        byte[] canon = new JsonCanonicalizer(json).getEncodedUTF8();
        byte[] dig = MessageDigest.getInstance("SHA-256").digest(canon);
        StringBuilder sb = new StringBuilder("sha256:");
        for (byte b : dig) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        JsonNode d = OM.readTree(new java.io.File(args[0]));
        int ok = 0;
        java.util.List<String> fails = new java.util.ArrayList<>();
        for (JsonNode v : d.get("vectors")) {
            try {
                if (dar(v, true).equals(v.get("expected_decision_audit_ref").asText())) ok++;
                else fails.add(v.get("id").asText() + ": accept-mismatch");
            } catch (Exception e) { fails.add(v.get("id").asText() + ": " + e.getMessage()); }
        }
        for (JsonNode n : d.get("negatives")) {
            String must = n.get("must").asText();
            if (must.equals("reject")) {
                try { dar(n, true); fails.add(n.get("id").asText() + ": invalid ACCEPTED"); }
                catch (Exception e) { ok++; }
            } else {
                String got = dar(n, true);
                if (!got.equals(n.get("claimed_decision_audit_ref").asText())) ok++;
                else fails.add(n.get("id").asText() + ": tamper NOT detected");
            }
        }
        JsonNode v0 = d.get("vectors").get(0);
        if (!dar(v0, true).equals(dar(v0, false))) ok++; else fails.add("screen-distinctness collision");
        ObjectNode bad = v0.deepCopy();
        bad.put("decision_ref", "bad");
        try { dar(bad, true); fails.add("malformed-ref accepted"); }
        catch (Exception e) { ok++; }

        int total = d.get("vectors").size() + d.get("negatives").size() + 2;
        for (String f : fails) System.out.println("  FAIL " + f);
        System.out.println("KEYSTONE-GAUNTLET java " + ok + "/" + total);
        if (ok != total || !fails.isEmpty()) System.exit(1);
    }
}
