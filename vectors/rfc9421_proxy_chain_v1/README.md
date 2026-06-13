# rfc9421_proxy_chain_v1

**Genuinely RFC 9421 §2.5-conformant** HTTP Message Signature survival fixture for a
3-hop proxy chain (CDN → reverse proxy → application server). This is the conformant
companion to [`rfc9421_proxy_chain_v0`](../rfc9421_proxy_chain_v0), which was signed
with the legacy **`algovoi-v0`** signing base and is retained as a labelled
algovoi-v0 survival set.

## What "conformant" means here

| Aspect | `rfc9421_proxy_chain_v0` (legacy) | `rfc9421_proxy_chain_v1` (this set) |
|---|---|---|
| `@method` value | lowercased (`get`) | **case-preserved (`GET`)** |
| `created` | carried as a **covered component** line | **signature parameter only** (no component line) |
| `@signature-params` line | **absent** | **present** as the final base line (RFC 9421 §2.5) |
| Verifier mode | `mode="algovoi-v0"` | `mode="rfc9421"` (the conformant default) |

The signing base for this set, exactly:

```
"@method": GET
"@authority": api.algovoi.co.uk
"@path": /compliance/attestation
"content-digest": sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:
"@signature-params": ("@method" "@authority" "@path" "content-digest");created=1778955520;keyid="did:web:api.algovoi.co.uk";alg="ed25519"
```

Signed with the **RFC 8032 §7.1 Test 1** Ed25519 keypair (deterministic — re-running
`generate.py` reproduces identical bytes).

## Cross-validation

Verified by **independent reimplementations** that each rebuild the conformant signing
base from scratch (no shared AlgoVoi code except the Python reference package):

| Runner | Ed25519 verify |
|---|---|
| `runner_python.py` (algovoi-rfc9421-verifier, `mode=rfc9421`) | ✅ |
| `runner_node.js` (inline + node:crypto) | ✅ |
| `runner_go.go` (inline + crypto/ed25519) | ✅ |
| `runner_java.java` (JDK 17 stdlib Ed25519) | ✅ |
| `runner_dotnet/` (NSec.Cryptography) | ✅ |
| `runner_ruby.rb` (inline + ed25519 gem) | ✅ |
| `runner_php.php` (inline + libsodium) | ✅ |
| `runner_rust/` (ed25519-dalek) | ✅ |

**All 8 implementations verify the full chain** (Python, Node, Go, Rust, Java, PHP, .NET,
Ruby), 2026-06-13 — matching the v0 set's 8/8 on the same host.

## Run

```bash
python runner_python.py     # pip install algovoi-rfc9421-verifier
ruby   runner_ruby.rb        # gem install ed25519
node   runner_node.js        # Node 18.4+ (built-in Ed25519)
go     run runner_go.go
php    runner_php.php         # requires ext-sodium
```

Each prints `PASS` and exits 0 on success.
