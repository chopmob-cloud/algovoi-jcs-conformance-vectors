// Differential adversarial substrate -- Kotlin/JVM canon probe (erdtman JCS).
// Contract: see probe_python.py. Emits "<id>\t h:<hex> | R:<reason>" per case.
@file:JvmName("Probe")
import java.security.MessageDigest
import org.erdtman.jcs.JsonCanonicalizer
import com.fasterxml.jackson.databind.ObjectMapper

val OM = ObjectMapper()

fun verdict(raw: String): String =
    try {
        val canon = JsonCanonicalizer(raw).encodedUTF8
        val dig = MessageDigest.getInstance("SHA-256").digest(canon)
        "h:" + dig.joinToString("") { "%02x".format(it) }
    } catch (e: Exception) {
        "R:err"
    }

fun main(args: Array<String>) {
    val d = OM.readTree(java.io.File(args[0]))
    val out = StringBuilder()
    for (c in d.get("cases")) {
        out.append(c.get("id").asText()).append('\t').append(verdict(c.get("raw").asText())).append('\n')
    }
    print(out)
}
