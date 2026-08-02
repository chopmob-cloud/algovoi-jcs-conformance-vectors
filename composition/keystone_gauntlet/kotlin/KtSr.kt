// settlement_round validity gauntlet -- Kotlin/JVM.
@file:JvmName("KtSr")
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
val OM = ObjectMapper()
fun rpiOk(v: JsonNode?): Boolean { if (v == null || v.isBoolean) return false; if (!v.isIntegralNumber) return false; return v.asLong() > 0 }
fun main(args: Array<String>) {
    val d = OM.readTree(java.io.File(args[0])); var ok = 0; val fails = mutableListOf<String>()
    for (r in d.get("settlement_round_reject_vectors")) { if (!rpiOk(r.get("receipt").get("settlement_round"))) ok++ else fails.add(r.get("vector_id").asText()) }
    var acc: JsonNode? = null
    for (v in d.get("vectors")) { val sr = v.path("receipt").get("settlement_round"); if (sr != null && sr.isIntegralNumber) { acc = v; break } }
    if (rpiOk(acc!!.get("receipt").get("settlement_round"))) ok++ else fails.add(acc.get("vector_id").asText())
    val total = d.get("settlement_round_reject_vectors").size() + 1
    for (f in fails) println("  FAIL $f")
    println("SETTLEMENT-ROUND-GAUNTLET kotlin $ok/$total")
    if (ok != total || fails.isNotEmpty()) kotlin.system.exitProcess(1)
}
