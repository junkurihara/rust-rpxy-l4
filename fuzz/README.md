# Parser fuzzing

Coverage-guided fuzzing of the first-party parsers in `rpxy-l4-quic-tls`, which handle
untrusted network bytes. The release profile uses `panic = "abort"`, so a reachable parser
panic is a whole-process denial of service. These targets catch such regressions early.

| Target | Entry point | Surface |
|---|---|---|
| `tls_clienthello` | `probe_tls_handshake_with_max_probe_bytes` | TLS records, ClientHello, all extensions (including ECH and outer extensions) |
| `quic_initial` | `probe_quic_initial_packets` | QUIC long header, header protection, AEAD attempt |
| `quic_frames` | `fuzzing::probe_quic_unprotected_payload` | Decrypted Initial payload: frames, CRYPTO reassembly, inner ClientHello |
| `ech_extension` | `fuzzing::probe_ech_extension` | ECH extension body |

The `fuzzing` module exists only with the default-off `fuzzing` feature of `rpxy-l4-quic-tls`.
This crate has its own workspace, so stable workspace builds never include it.

Not covered here: PROXY protocol parsing (async and delegated to `ppp`), ECH inner
ClientHello recomposition after HPKE decryption, and the trivial TCP/WireGuard detectors.

## Layout

- `seed_corpus/<target>/` is tracked and read-only: known crash boundaries and valid inputs.
- `corpus/<target>/` is the ignored, writable corpus that libFuzzer grows.
- `artifacts/<target>/` is where crashing inputs are written (ignored).
- `Cargo.lock` is not tracked. It is derived from the root `Cargo.lock`, so the parser is fuzzed
  against exactly the dependency versions that ship.

## Running locally

Fuzzing needs a nightly toolchain and `cargo-fuzz`. First set the two pins as shell variables,
copying their values from the `env` section of `.github/workflows/fuzz.yml`:

```sh
FUZZ_NIGHTLY=nightly-YYYY-MM-DD   # value of FUZZ_NIGHTLY in the workflow
CARGO_FUZZ_VERSION=X.Y.Z          # value of CARGO_FUZZ_VERSION in the workflow
```

Then install the tools, derive the lockfile, and run a target:

```sh
rustup toolchain install "$FUZZ_NIGHTLY" --profile minimal
cargo install cargo-fuzz --version "$CARGO_FUZZ_VERSION" --locked

cp Cargo.lock fuzz/Cargo.lock
cargo fetch --manifest-path fuzz/Cargo.toml

mkdir -p fuzz/corpus/tls_clienthello
cargo +"$FUZZ_NIGHTLY" fuzz run tls_clienthello \
  fuzz/corpus/tls_clienthello fuzz/seed_corpus/tls_clienthello -- -max_total_time=60
```

Always pass the writable `corpus/<target>` first. libFuzzer writes new inputs only to the
first corpus directory, and the seed corpus must stay unchanged.

Copying the root lockfile keeps every shared dependency at its shipped version. Cargo then adds
only the fuzz-only crates and prunes the rest. Repeat the two lockfile commands after the root
`Cargo.lock` changes.

## Triage

`cargo fuzz` builds with debug assertions and overflow checks by default. The shipped release
build has overflow checks off, so a fuzz crash does not always mean the release binary aborts.
Replay a crash both ways and record the difference:

```sh
cargo +"$FUZZ_NIGHTLY" fuzz run <target> fuzz/artifacts/<target>/<crash-file>
cargo +"$FUZZ_NIGHTLY" fuzz run -O <target> fuzz/artifacts/<target>/<crash-file>
```

For each new crash: add the input to `seed_corpus/<target>/`, add a regression `#[test]` in
`rpxy-l4-quic-tls`, and fix the root cause.

## Updating the pins

The nightly date, `cargo-fuzz` (both in the workflow), and `libfuzzer-sys` (exact in
`fuzz/Cargo.toml`) are bumped manually and together, then confirmed by a green CI build and
smoke run. Dependency updates of the parser crates need no fuzz-side change, because the fuzz
lockfile follows the root `Cargo.lock`.

The pinned nightly must not be older than the workspace `rust-version`. Review the nightly pin
whenever `rust-version` is raised to the nightly's minor version or above.
