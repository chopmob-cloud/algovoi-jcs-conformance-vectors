// Retention Chain v0 vector runner -- Kotlin / JVM / java-json-canonicalization 1.1
//
// Validates sha256(JCS(preimage)) == expected_chain_ref
//
// Build & run:
//   cd runner_kotlin
//   ./gradlew run --args="<vector_set_json>"
//
// Or standalone with JAR on classpath:
//   kotlinc -cp "libs/*" src/main/kotlin/Runner.kt -include-runtime -d runner.jar
//   java -cp "runner.jar;libs/*" RunnerKt <vector_set_json>

import org.erdtman.jcs.JsonCanonicalizer
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.File
import java.security.MessageDigest
import java.util.Base64

fun sha256Jcs(om: ObjectMapper, nodeJson: String): Pair<String, String> {
    val jc = JsonCanonicalizer(nodeJson)
    val canonBytes = jc.encodedUTF8
    val b64 = Base64.getEncoder().encodeToString(canonBytes)
    val digest = MessageDigest.getInstance("SHA-256").digest(canonBytes)
    val hex = digest.joinToString("") { "%02x".format(it) }
    return b64 to "sha256:$hex"
}

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        System.err.println("usage: runner_kotlin <vector_set_json>")
        System.exit(2)
    }
    val om = ObjectMapper()
    val data = om.readTree(File(args[0]))
    val vectors = data.get("vectors")

    var pass = 0; var fail = 0

    for (v in vectors) {
        val vid      = v.get("vector_id").asText()
        val preJson  = om.writeValueAsString(v.get("preimage"))
        val (b64, ref) = sha256Jcs(om, preJson)

        val b64Ok = b64 == v.get("expected_jcs_bytes_b64").asText()
        val refOk = ref == v.get("expected_chain_ref").asText()

        if (b64Ok && refOk) {
            pass++
        } else {
            fail++
            if (!b64Ok) println("  FAIL $vid jcs_bytes_b64 mismatch")
            if (!refOk) println("  FAIL $vid chain_ref (got $ref)")
        }
    }
    println("$pass/${pass + fail} PASS")
    if (fail > 0) System.exit(1)
}
