// revocation_ref fail-closed gauntlet -- Kotlin/JVM (erdtman JCS).
@file:JvmName("KtRev")
import java.security.MessageDigest
import java.util.Objects
import org.erdtman.jcs.JsonCanonicalizer
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
val OM = ObjectMapper(); val REF = Regex("^sha256:[0-9a-f]{64}$")
val REASONS = setOf("USER_REQUESTED", "COMPLIANCE_TRIGGERED", "EXPIRED", "KEY_COMPROMISE", "SUPERSEDED", "ADMIN")
val STATUS = setOf("active", "suspended", "revoked", "inactive")
fun hjcs(o: JsonNode): String { val canon = JsonCanonicalizer(OM.writeValueAsString(o)).encodedUTF8; return "sha256:" + MessageDigest.getInstance("SHA-256").digest(canon).joinToString("") { "%02x".format(it) } }
fun refF(f: JsonNode, k: String): String { val v = f.get(k); if (v == null || !v.isTextual || !REF.matches(v.asText())) throw IllegalArgumentException(k); return v.asText() }
fun intF(f: JsonNode, k: String): Long { val v = f.get(k); if (v == null || !v.isIntegralNumber || v.asLong() < 0) throw IllegalArgumentException(k); return v.asLong() }
fun enumF(f: JsonNode, k: String, a: Set<String>): String { val v = f.get(k); if (v == null || !v.isTextual || !a.contains(v.asText())) throw IllegalArgumentException(k); return v.asText() }
fun strF(f: JsonNode, k: String): String { val v = f.get(k); if (v == null || !v.isTextual || v.asText().isEmpty()) throw IllegalArgumentException(k); return v.asText() }
fun rref(f: JsonNode): String {
    val o = OM.createObjectNode()
    o.put("canon_version", "jcs-rfc8785-v1"); o.put("type", "revocation_link")
    o.put("subject_ref", refF(f, "subject_ref")); o.put("revoked_at_ms", intF(f, "revoked_at_ms"))
    o.put("reason_code", enumF(f, "reason_code", REASONS)); o.put("issuer_did", strF(f, "issuer_did"))
    o.put("prev_status", enumF(f, "prev_status", STATUS)); o.put("new_status", enumF(f, "new_status", STATUS)); o.put("seq", intF(f, "seq"))
    val p = f.get("prev_revocation_ref"); if (p == null || p.isNull) o.putNull("prev_revocation_ref") else o.put("prev_revocation_ref", refF(f, "prev_revocation_ref"))
    return hjcs(o)
}
fun vchain(links: JsonNode): Boolean {
    var prev: String? = null; var i = 0
    for (l in links) {
        val sq = l.get("seq"); if (sq == null || !sq.isIntegralNumber || sq.asInt() != i) return false
        val pn = l.get("prev_revocation_ref"); val lp = if (pn == null || pn.isNull) null else pn.asText()
        if (!Objects.equals(lp, prev)) return false
        prev = hjcs(l); i++
    }
    return true
}
fun main(args: Array<String>) {
    val d = OM.readTree(java.io.File(args[0])); var ok = 0; val fails = mutableListOf<String>()
    for (v in d.get("vectors")) { try { if (rref(v) == v.get("expected_revocation_ref").asText()) ok++ else fails.add(v.get("id").asText()) } catch (e: Exception) { fails.add(v.get("id").asText()) } }
    for (n in d.get("negatives")) { try { rref(n); fails.add(n.get("id").asText()) } catch (e: Exception) { ok++ } }
    for (t in d.get("tamper")) { if (rref(t) != t.get("claimed_revocation_ref").asText()) ok++ else fails.add(t.get("id").asText()) }
    for (c in d.get("chain_valid")) { if (vchain(c.get("links"))) ok++ else fails.add(c.get("id").asText()) }
    for (c in d.get("chain_invalid")) { if (!vchain(c.get("links"))) ok++ else fails.add(c.get("id").asText()) }
    val total = d.get("vectors").size() + d.get("negatives").size() + d.get("tamper").size() + d.get("chain_valid").size() + d.get("chain_invalid").size()
    for (f in fails) println("  FAIL $f")
    println("REVOCATION-GAUNTLET kotlin $ok/$total")
    if (ok != total || fails.isNotEmpty()) kotlin.system.exitProcess(1)
}
