// trust_gate deny-table gauntlet -- Kotlin/JVM.
@file:JvmName("KtTg")
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
val OM = ObjectMapper()
val DENY = mapOf("block_untrusted" to setOf("UNTRUSTED"), "require_trusted" to setOf("UNTRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE"))
fun blocks(mode: JsonNode?, verdict: String): Boolean {
    if (mode == null || mode.isNull || !mode.isTextual) return false
    val m = mode.asText(); if (m.isEmpty() || m == "off") return false
    return DENY.getOrDefault(m, emptySet()).contains(verdict)
}
fun main(args: Array<String>) {
    val d = OM.readTree(java.io.File(args[0])); var ok = 0; val fails = mutableListOf<String>()
    for (v in d.get("vectors")) { if (blocks(v.get("mode"), v.get("verdict").asText()) == v.get("expected_blocks").asBoolean()) ok++ else fails.add(v.get("id").asText()) }
    val total = d.get("vectors").size()
    for (f in fails) println("  FAIL $f")
    println("TRUST-GATE-GAUNTLET kotlin $ok/$total")
    if (ok != total || fails.isNotEmpty()) kotlin.system.exitProcess(1)
}
