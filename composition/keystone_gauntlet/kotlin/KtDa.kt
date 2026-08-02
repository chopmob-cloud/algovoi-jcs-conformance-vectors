// Keystone L3 gauntlet -- decision_audit, Kotlin/JVM (erdtman JCS).
@file:JvmName("KtDa")
import java.security.MessageDigest
import org.erdtman.jcs.JsonCanonicalizer
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode

val OM = ObjectMapper()
val REF = Regex("^sha256:[0-9a-f]{64}$")

fun buildAudit(src: JsonNode, withScreen: Boolean): ObjectNode {
    val o = OM.createObjectNode()
    for (k in listOf("decision_ref", "passport_credential_ref", "mandate_ref", "policy_bound_ref")) {
        val v = src.get(k)
        if (v == null || !v.isTextual || !REF.matches(v.asText())) throw IllegalArgumentException(k)
        o.put(k, v.asText())
    }
    val sbr = src.get("screen_binding_ref")
    if (withScreen && sbr != null && !sbr.isNull) {
        if (!sbr.isTextual || !REF.matches(sbr.asText())) throw IllegalArgumentException("sbr")
        o.put("screen_binding_ref", sbr.asText())
    }
    return o
}
fun dar(src: JsonNode, withScreen: Boolean): String {
    val canon = JsonCanonicalizer(OM.writeValueAsString(buildAudit(src, withScreen))).encodedUTF8
    return "sha256:" + MessageDigest.getInstance("SHA-256").digest(canon).joinToString("") { "%02x".format(it) }
}
fun main(args: Array<String>) {
    val d = OM.readTree(java.io.File(args[0]))
    var ok = 0; val fails = mutableListOf<String>()
    for (v in d.get("vectors")) {
        try { if (dar(v, true) == v.get("expected_decision_audit_ref").asText()) ok++ else fails.add(v.get("id").asText()) }
        catch (e: Exception) { fails.add(v.get("id").asText()) }
    }
    for (n in d.get("negatives")) {
        if (n.get("must").asText() == "reject") { try { dar(n, true); fails.add(n.get("id").asText()) } catch (e: Exception) { ok++ } }
        else { if (dar(n, true) != n.get("claimed_decision_audit_ref").asText()) ok++ else fails.add(n.get("id").asText()) }
    }
    val v0 = d.get("vectors").get(0)
    if (dar(v0, true) != dar(v0, false)) ok++ else fails.add("screen-distinctness")
    val bad = v0.deepCopy<ObjectNode>(); bad.put("decision_ref", "bad")
    try { dar(bad, true); fails.add("malformed") } catch (e: Exception) { ok++ }
    val total = d.get("vectors").size() + d.get("negatives").size() + 2
    for (f in fails) println("  FAIL $f")
    println("KEYSTONE-GAUNTLET kotlin $ok/$total")
    if (ok != total || fails.isNotEmpty()) kotlin.system.exitProcess(1)
}
