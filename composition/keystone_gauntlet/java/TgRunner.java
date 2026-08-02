// trust_gate deny-table gauntlet -- Java impl.
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
public class TgRunner {
	static final java.util.Map<String, java.util.Set<String>> DENY = java.util.Map.of(
		"block_untrusted", java.util.Set.of("UNTRUSTED"),
		"require_trusted", java.util.Set.of("UNTRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE"));
	static boolean blocks(JsonNode mode, String verdict) {
		if (mode == null || mode.isNull() || !mode.isTextual()) return false;
		String m = mode.asText();
		if (m.isEmpty() || m.equals("off")) return false;
		return DENY.getOrDefault(m, java.util.Set.of()).contains(verdict);
	}
	public static void main(String[] a) throws Exception {
		ObjectMapper om = new ObjectMapper(); JsonNode d = om.readTree(new java.io.File(a[0]));
		int ok = 0; var fails = new java.util.ArrayList<String>();
		for (JsonNode v : d.get("vectors")) {
			if (blocks(v.get("mode"), v.get("verdict").asText()) == v.get("expected_blocks").asBoolean()) ok++;
			else fails.add(v.get("id").asText() + ": mismatch");
		}
		int total = d.get("vectors").size();
		for (String f : fails) System.out.println("  FAIL " + f);
		System.out.println("TRUST-GATE-GAUNTLET java " + ok + "/" + total);
		if (ok != total || !fails.isEmpty()) System.exit(1);
	}
}
