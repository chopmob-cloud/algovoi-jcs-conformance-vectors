// revocation_ref fail-closed gauntlet -- Java 17 (erdtman JCS).
// Build: javac -cp "libs/*" RevRunner.java ; Run: java -cp ".;libs/*" RevRunner <json>
import java.security.MessageDigest;
import java.util.Objects;
import org.erdtman.jcs.JsonCanonicalizer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class RevRunner {
	static final String REF = "^sha256:[0-9a-f]{64}$";
	static final ObjectMapper OM = new ObjectMapper();
	static final java.util.Set<String> REASONS = java.util.Set.of("USER_REQUESTED","COMPLIANCE_TRIGGERED","EXPIRED","KEY_COMPROMISE","SUPERSEDED","ADMIN");
	static final java.util.Set<String> STATUS = java.util.Set.of("active","suspended","revoked","inactive");

	static String hjcs(JsonNode o) throws Exception {
		byte[] canon = new JsonCanonicalizer(OM.writeValueAsString(o)).getEncodedUTF8();
		byte[] dig = MessageDigest.getInstance("SHA-256").digest(canon);
		StringBuilder sb = new StringBuilder("sha256:");
		for (byte b : dig) sb.append(String.format("%02x", b));
		return sb.toString();
	}
	static String refField(JsonNode f, String k) { JsonNode v = f.get(k); if (v==null||!v.isTextual()||!v.asText().matches(REF)) throw new IllegalArgumentException(k); return v.asText(); }
	static long intField(JsonNode f, String k) { JsonNode v = f.get(k); if (v==null||!v.isIntegralNumber()||v.asLong()<0) throw new IllegalArgumentException(k); return v.asLong(); }
	static String enumField(JsonNode f, String k, java.util.Set<String> a) { JsonNode v = f.get(k); if (v==null||!v.isTextual()||!a.contains(v.asText())) throw new IllegalArgumentException(k); return v.asText(); }
	static String strField(JsonNode f, String k) { JsonNode v = f.get(k); if (v==null||!v.isTextual()||v.asText().isEmpty()) throw new IllegalArgumentException(k); return v.asText(); }

	static String rref(JsonNode f) throws Exception {
		ObjectNode o = OM.createObjectNode();
		o.put("canon_version","jcs-rfc8785-v1"); o.put("type","revocation_link");
		o.put("subject_ref", refField(f,"subject_ref"));
		o.put("revoked_at_ms", intField(f,"revoked_at_ms"));
		o.put("reason_code", enumField(f,"reason_code",REASONS));
		o.put("issuer_did", strField(f,"issuer_did"));
		o.put("prev_status", enumField(f,"prev_status",STATUS));
		o.put("new_status", enumField(f,"new_status",STATUS));
		o.put("seq", intField(f,"seq"));
		JsonNode p = f.get("prev_revocation_ref");
		if (p==null||p.isNull()) o.putNull("prev_revocation_ref");
		else o.put("prev_revocation_ref", refField(f,"prev_revocation_ref"));
		return hjcs(o);
	}
	static boolean vchain(JsonNode links) throws Exception {
		String prev = null; int i = 0;
		for (JsonNode l : links) {
			JsonNode sq = l.get("seq"); if (sq==null||!sq.isIntegralNumber()||sq.asInt()!=i) return false;
			JsonNode pn = l.get("prev_revocation_ref"); String lp = (pn==null||pn.isNull())?null:pn.asText();
			if (!Objects.equals(lp, prev)) return false;
			prev = hjcs(l); i++;
		}
		return true;
	}
	public static void main(String[] a) throws Exception {
		JsonNode d = OM.readTree(new java.io.File(a[0]));
		int ok = 0; var fails = new java.util.ArrayList<String>();
		for (JsonNode v : d.get("vectors")) { try { if (rref(v).equals(v.get("expected_revocation_ref").asText())) ok++; else fails.add(v.get("id").asText()); } catch (Exception e) { fails.add(v.get("id").asText()); } }
		for (JsonNode n : d.get("negatives")) { try { rref(n); fails.add(n.get("id").asText()); } catch (Exception e) { ok++; } }
		for (JsonNode t : d.get("tamper")) { if (!rref(t).equals(t.get("claimed_revocation_ref").asText())) ok++; else fails.add(t.get("id").asText()); }
		for (JsonNode c : d.get("chain_valid")) { if (vchain(c.get("links"))) ok++; else fails.add(c.get("id").asText()); }
		for (JsonNode c : d.get("chain_invalid")) { if (!vchain(c.get("links"))) ok++; else fails.add(c.get("id").asText()); }
		int total = d.get("vectors").size()+d.get("negatives").size()+d.get("tamper").size()+d.get("chain_valid").size()+d.get("chain_invalid").size();
		for (String f : fails) System.out.println("  FAIL " + f);
		System.out.println("REVOCATION-GAUNTLET java " + ok + "/" + total);
		if (ok != total || !fails.isEmpty()) System.exit(1);
	}
}
