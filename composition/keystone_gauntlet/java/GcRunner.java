// Keystone L3 gauntlet -- guard_context, Java 17 (erdtman JCS).
// Build: javac -cp "libs/*" GcRunner.java ; Run: java -cp ".;libs/*" GcRunner <json>
import java.security.MessageDigest;

import org.erdtman.jcs.JsonCanonicalizer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class GcRunner {
    static final String REF = "^sha256:[0-9a-f]{64}$";
    static final ObjectMapper OM = new ObjectMapper();

    static String dar(JsonNode src) throws Exception {
        JsonNode tsNode = src.get("guard_timestamp_ms");
        if (tsNode == null || !tsNode.isIntegralNumber() || tsNode.asLong() < 0)
            throw new IllegalArgumentException("guard_timestamp_ms must be non-negative integer");
        ObjectNode o = OM.createObjectNode();
        o.put("canon_version", "jcs-rfc8785-v1");
        o.put("type", "guard_context");
        o.put("guard_timestamp_ms", tsNode.asLong());
        for (String k : new String[]{"policy_ref", "mandate_ref", "passport_credential_ref"}) {
            JsonNode val = src.get(k);
            if (val == null || !val.isTextual() || !val.asText().matches(REF))
                throw new IllegalArgumentException(k + " must be sha256: ref");
            o.put(k, val.asText());
        }
        byte[] canon = new JsonCanonicalizer(OM.writeValueAsString(o)).getEncodedUTF8();
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
            try { if (dar(v).equals(v.get("expected_guard_context_ref").asText())) ok++; else fails.add(v.get("id").asText() + ": accept-mismatch"); }
            catch (Exception e) { fails.add(v.get("id").asText() + ": " + e.getMessage()); }
        }
        for (JsonNode n : d.get("negatives")) {
            if (n.get("must").asText().equals("reject")) {
                try { dar(n); fails.add(n.get("id").asText() + ": invalid ACCEPTED"); }
                catch (Exception e) { ok++; }
            } else {
                if (!dar(n).equals(n.get("claimed_guard_context_ref").asText())) ok++;
                else fails.add(n.get("id").asText() + ": tamper NOT detected");
            }
        }
        JsonNode v0 = d.get("vectors").get(0);
        ObjectNode plus = v0.deepCopy();
        plus.put("guard_timestamp_ms", v0.get("guard_timestamp_ms").asLong() + 1);
        if (!dar(v0).equals(dar(plus))) ok++; else fails.add("moment-distinctness collision");
        ObjectNode flt = v0.deepCopy();
        flt.put("guard_timestamp_ms", 1720000000000.5);
        try { dar(flt); fails.add("float-ts accepted"); }
        catch (Exception e) { ok++; }

        int total = d.get("vectors").size() + d.get("negatives").size() + 2;
        for (String f : fails) System.out.println("  FAIL " + f);
        System.out.println("KEYSTONE-GAUNTLET-GC java " + ok + "/" + total);
        if (ok != total || !fails.isEmpty()) System.exit(1);
    }
}
