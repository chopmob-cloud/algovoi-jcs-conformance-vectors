# Rust corpus sweep — 2026-06-17

**All four Rust runners: PASS.**

| Set | Vectors | Result |
|---|---|---|
| `retention_chain_v0` | 3 | 3/3 PASS |
| `retention_chain_v1` | 14 | 14/14 PASS |
| `epi_interop_v0` | 5 | 5/5 PASS |
| `epi_pqc_v0` | 4 | 4/4 PASS (JCS only; Falcon key-gen is Python-only) |

**Total: 26/26 PASS across 4 sets.**

## Method

Toolchain: `stable-x86_64-pc-windows-gnu` (GNU Rust toolchain, pre-installed via `rustup`).

Linker: `x86_64-w64-mingw32-gcc.exe` from WinLibs POSIX/MSVCRT/LLVM (BrechtSanders WinGet package), added to `PATH` before invoking cargo.

Command for each set:
```
export PATH="<winlibs-mingw64-bin>:$PATH"
cd vectors/<set>/runner_rust
cargo +stable-x86_64-pc-windows-gnu run -q -- ../<set>.json
```

## Windows environment note

The default Rust toolchain on this machine is `stable-x86_64-pc-windows-msvc`. That toolchain requires MSVC Build Tools + Windows SDK to link. Neither is installed, so the MSVC toolchain cannot link.

The MSYS2/Git `/usr/bin/link` (GNU binutils) shadows MSVC's `link.exe` in the shell PATH, causing confusing errors when the MSVC toolchain tries to link (`link: extra operand`).

**Fix**: use the `stable-x86_64-pc-windows-gnu` toolchain with `x86_64-w64-mingw32-gcc` from WinLibs as the linker. This avoids MSVC tooling entirely. Build scripts and the final binary both compile with GNU tools.

`.cargo/config.toml` files with a machine-specific WinLibs path were used locally during development; they are gitignored (`.cargo/` in root `.gitignore`) and not committed.

## Context

This sweep was run as part of the corpus v0.9.0 closeout (21 sets, 166 vectors, 832/832 cumulative byte-for-byte agreements). Rust is one of eight implementations in the cross-language matrix.
