// Keystone L3 gauntlet -- guard_context, Kotlin/JVM (erdtman JCS).
@file:JvmName("KtGc")
import java.security.MessageDigest
import org.erdtman.jcs.JsonCanonicalizer
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
val OM = ObjectMapper(); val REF = Regex("^sha256:[0-9a-f]{64}$")
fun dar(src: JsonNode): String {
    val ts = src.get("guard_timestamp_ms")
    if (ts == null || !ts.isIntegralNumber || ts.asLong() < 0) throw IllegalArgumentException("ts")
    val o = OM.createObjectNode()
    o.put("canon_version", "jcs-rfc8785-v1"); o.put("type", "guard_context"); o.put("guard_timestamp_ms", ts.asLong())
    for (k in listOf("policy_ref", "mandate_ref", "passport_credential_ref")) {
        val v = src.get(k); if (v == null || !v.isTextual || !REF.matches(v.asText())) throw IllegalArgumentException(k); o.put(k, v.asText())
    }
    val canon = JsonCanonicalizer(OM.writeValueAsString(o)).encodedUTF8
    return "sha256:" + MessageDigest.getInstance("SHA-256").digest(canon).joinToString("") { "%02x".format(it) }
}
fun main(args: Array<String>) {
    val d = OM.readTree(java.io.File(args[0])); var ok = 0; val fails = mutableListOf<String>()
    for (v in d.get("vectors")) { try { if (dar(v) == v.get("expected_guard_context_ref").asText()) ok++ else fails.add(v.get("id").asText()) } catch (e: Exception) { fails.add(v.get("id").asText()) } }
    for (n in d.get("negatives")) { if (n.get("must").asText() == "reject") { try { dar(n); fails.add(n.get("id").asText()) } catch (e: Exception) { ok++ } } else { if (dar(n) != n.get("claimed_guard_context_ref").asText()) ok++ else fails.add(n.get("id").asText()) } }
    val v0 = d.get("vectors").get(0)
    val plus = v0.deepCopy<ObjectNode>(); plus.put("guard_timestamp_ms", v0.get("guard_timestamp_ms").asLong() + 1)
    if (dar(v0) != dar(plus)) ok++ else fails.add("moment")
    val flt = v0.deepCopy<ObjectNode>(); flt.put("guard_timestamp_ms", 1720000000000.5)
    try { dar(flt); fails.add("float") } catch (e: Exception) { ok++ }
    val total = d.get("vectors").size() + d.get("negatives").size() + 2
    for (f in fails) println("  FAIL $f")
    println("KEYSTONE-GAUNTLET-GC kotlin $ok/$total")
    if (ok != total || fails.isNotEmpty()) kotlin.system.exitProcess(1)
}
