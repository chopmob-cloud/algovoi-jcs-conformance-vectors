// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE in this directory.
// Generic JCS hash-comparison runner -- Kotlin / JVM / java-json-canonicalization 1.1
//
// Validates sha256(JCS(vector[payloadField])) == vector[hashField] (optionally
// "sha256:"-prefixed) for every vector in a set's JSON file. payloadFields and
// hashFields may each be a comma-separated fallback list (e.g. "receipt,row") --
// the first key actually present on the vector is used, matching this corpus's
// own reference runners where different vector kinds (receipts vs. audit chain
// rows) use different field names within the same set.
//
// Usage: java -cp "GenericRunner.jar;<jars>" GenericRunnerKt <json> <payloadFields> <hashFields> <prefix:0|1> [b64Fields]

import org.erdtman.jcs.JsonCanonicalizer
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.File
import java.security.MessageDigest
import java.util.Base64

fun firstPresent(v: JsonNode, fields: List<String>): Pair<String, JsonNode>? {
    for (f in fields) {
        if (v.has(f)) return f to v.get(f)
    }
    return null
}

fun main(args: Array<String>) {
    val path = args[0]
    val payloadFields = args[1].split(",")
    val hashFields = args[2].split(",")
    val prefix = if (args[3] == "1") "sha256:" else ""
    val b64Fields = args.getOrNull(4)?.split(",") ?: emptyList()

    val om = ObjectMapper()
    val data = om.readTree(File(path))
    var pass = 0; var fail = 0

    for (v in data.get("vectors")) {
        val vid = (v.get("vector_id") ?: v.get("id")).asText()
        val (_, payload) = firstPresent(v, payloadFields) ?: error("no payload field for $vid")
        val (hfield, hexp) = firstPresent(v, hashFields) ?: error("no hash field for $vid")

        val preJson = om.writeValueAsString(payload)
        val jc = JsonCanonicalizer(preJson)
        val canonBytes = jc.encodedUTF8
        val b64 = Base64.getEncoder().encodeToString(canonBytes)
        val digest = MessageDigest.getInstance("SHA-256").digest(canonBytes)
        val hex = digest.joinToString("") { "%02x".format(it) }
        val ref = prefix + hex

        val hashOk = ref == hexp.asText()
        val b64Match = firstPresent(v, b64Fields)
        val b64Ok = b64Match == null || b64 == b64Match.second.asText()

        if (!hashOk) println("  FAIL $vid $hfield mismatch (got $ref, expected ${hexp.asText()})")
        if (!b64Ok) println("  FAIL $vid jcs_bytes_b64 mismatch")

        if (hashOk && b64Ok) pass++ else fail++
    }
    println("$pass/${pass + fail} PASS")
    if (fail > 0) System.exit(1)
}
