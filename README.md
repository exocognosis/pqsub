# pqsub: a post-quantum cryptographic substrate for multi-agent systems

`pqsub` gives AI agents a post-quantum identity, signed handoffs and tool-call authorizations, and hash-chained traces. Anyone holding the operator's root public key can verify a trace without trusting the agent that produced it.

- **Signatures:** ML-DSA-65 ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)), pure mode with context strings.
- **Hashing:** SHA3-256.
- **Language:** pure Rust, no `unsafe`, no network.
- **Specs:** byte formats and verification order in [docs/DESIGN.md](docs/DESIGN.md); threat model in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

```
crates/pqsub-core     library: keys · identity docs · manifests · traces · key store      (RustCrypto ml-dsa)
crates/pqsub-cli      `pqsub` CLI · 4-agent simulation · vector generator · benchmarks
crates/pqsub-verify   independent verifier lib + `pqsub-verify` bin, from spec, no shared code (fips204)
test-vectors/         vectors.json: 25 transcript cases + keygen/signature vectors
examples/demo/        deterministic demo transcript (binary + text) and its inputs
```

## Build and test on a MacBook Air (Apple silicon)

Requirements:
- Xcode command-line tools: `xcode-select --install`
- rustup: <https://rustup.rs>

`rust-toolchain.toml` pins Rust 1.99.1, and rustup installs it automatically. The project directory name has a trailing space, so quote paths when you `cd`.

```bash
cargo build --release --locked
```

```bash
cargo test --workspace --locked
```

```bash
cargo clippy --workspace --all-targets --locked
```

The full test suite takes about 50 s on the development machine (MacBook Air, Apple M3, 16 GB). Most of that time goes to the exhaustive cross-implementation bit-flip test. Dependencies are built with `opt-level=3` even in the test profile, because unoptimized ML-DSA is much slower.

## Demo: four-agent handoff with a verifiable transcript

```bash
./target/release/pqsub simulate --deterministic --out demo-out
```

The simulation runs four agents:
1. The orchestrator hands the task to the researcher.
2. The researcher hands off to the coder.
3. The coder signs a sandbox **tool authorization**.
4. The coder hands off to the reviewer.
5. The reviewer signs an **action record**.
6. The orchestrator authorizes the merge.

The run writes `keys/` (mode 0700), `root.pub`, `identities/`, `payloads/`, `transcript.pqst`, `transcript.txt`, `checkpoint.txt` and `head.txt`. The committed output is in [examples/demo/transcript.txt](examples/demo/transcript.txt). Leave out `--deterministic` to get fresh random keys and hedged signatures.

A third-party auditor runs the independent verifier, which shares no code with the producer:

```bash
./target/release/pqsub-verify transcript --root demo-out/root.pub demo-out/transcript.pqst --expect-head "$(cat demo-out/head.txt)"
```

To verify only a suffix, anchor it at a published checkpoint:

```bash
./target/release/pqsub-verify transcript --root demo-out/root.pub demo-out/transcript.pqst --from 3 --anchor "$(cat demo-out/checkpoint.txt)"
```

To check that the evidence is tamper-evident, flip one bit and verify again. The command exits with status 2 and prints `INVALID [BAD_SIGNATURE] entry 5` (the last entry's signature):

```bash
python3 -c "import sys;p='demo-out/transcript.pqst';b=bytearray(open(p,'rb').read());b[-100]^=1;open(p,'wb').write(b)" && ./target/release/pqsub-verify transcript --root demo-out/root.pub demo-out/transcript.pqst
```

## CLI walkthrough

```bash
pqsub root-init  --keys keys --pub-out root.pub                     # operator / trust-anchor key
pqsub agent-new  --keys keys --name alice --role planner --out alice.id
pqsub agent-new  --keys keys --name bob   --role executor --out bob.id

# standalone signed handoff, binding a payload file by hash
pqsub sign   --key keys/alice.key --to-agent bob.id --intent "deploy v1.2 to staging" --payload task.txt --out h.pqsm
pqsub verify --root root.pub --identity alice.id h.pqsm --payload task.txt

# append-only trace (the existing transcript is verified before each append)
pqsub append --root root.pub --transcript t.pqst --key keys/alice.key --identity alice.id --to-agent bob.id --intent "deploy"
pqsub append --root root.pub --transcript t.pqst --key keys/bob.key --identity bob.id --kind tool-auth --to-role deployer --intent "run deploy.sh"
pqsub verify-trace --root root.pub t.pqst [--from N] [--anchor genesis|none|HEX] [--expect-head HEX] [--show]

pqsub inspect FILE          # pretty-print any artifact (no verification)
pqsub hash FILE             # payload digest
pqsub gen-vectors           # regenerate test-vectors/vectors.json (must be byte-identical)
pqsub bench                 # micro-benchmarks
```

`verify`, `verify-trace` and `pqsub-verify` print `VALID …` and exit 0, or print `INVALID [CODE] …` and exit 2. The codes are listed in DESIGN §3.

## Library API (core)

```rust
use pqsub_core::*;
let root  = AgentKeypair::generate()?;
let alice = AgentKeypair::generate()?;
let id = IdentityDocument::issue(&root, alice.public_key(),
    IdentityClaims { name: "alice".into(), role: "planner".into(), not_before_ms: t0, not_after_ms: t1 },
    SigningMode::Hedged)?;
let mut trace = TraceBuilder::new();
trace.append(&alice, EntrySpec { kind: ManifestKind::Handoff, recipient: Recipient::Role("executor".into()),
    intent: "deploy".into(), payload_hash: Some(payload_hash(b"...")), timestamp_ms: now }, SigningMode::Hedged)?;
let t = Transcript { identities: vec![id], entries: trace.into_entries() };
let report = t.verify(root.public_key(), 0, &VerifyOptions::default())?; // report.head, per-entry hashes
```

pqsub's library code does not use `unwrap`, `expect` or `panic`, and clippy denies all three. (The underlying `ml-dsa` signer can panic in a negligible-probability rejection-sampling edge case; see the threat model.) Every error has a stable `code()`.

## Security properties claimed

The [threat model](docs/THREAT_MODEL.md) has the details and the limits. In short:
- Every manifest and identity document is authentic. Any modification, including a single-bit flip, fails verification.
- An identity is accepted only if the root signed it **and** `agent_id = SHA3(pk)`. A manifest verifies only under its declared sender's key.
- A trace detects reordering, deletion, insertion, splicing, duplication and per-sender seq replay. Truncation is detected when the verifier pins `--anchor` and `--expect-head`.
- Verification needs only `root.pub`, obtained out of band, plus the transcript. Two independent ML-DSA implementations agree on every test vector.

The following are **not** provided:
- confidentiality
- revocation
- trusted time
- recipient binding at verification time (receivers must check the `recipient` field themselves)
- protection against a compromised agent or root key
- keys encrypted at rest
- a guarantee that a signed intent is *safe* (signed text is still untrusted LLM input)

## Evidence

| Check | Result |
|---|---|
| `pqsub-core` unit and integration tests | 25 pass. Includes an exhaustive single-bit flip over all ≈ 28k bits of a manifest, and tamper/reorder/drop/truncate/replay/expiry/identity cases |
| Cross-implementation tests | 5 pass:<br>• the two implementations give byte-identical keygen and signatures<br>• ≈ 29k bit flips get identical error codes from both<br>• 400 random mutations agree |
| CLI end-to-end and reproducibility | 5 pass:<br>• the committed vectors match regeneration<br>• the demo transcript is byte-reproducible<br>• the full CLI workflow passes, including tamper, wrong root and payload mismatch |
| `pqsub-verify vectors test-vectors/vectors.json` | `ALL VECTORS PASS (37 checks)` |

Benchmarks, measured with `./target/release/pqsub bench --iters 300` on the development machine, a MacBook Air with an Apple M3 and 16 GB. They have **not** yet been measured on an M4; run the same command there to get M4 numbers:

| Operation | Time |
|---|---|
| keygen (from seed) | 308 µs |
| sign (deterministic) | 301 µs |
| sign (hedged) | 459 µs |
| verify (cached pk) | 57 µs |
| decode pk + verify | 110 µs |
| strict manifest decode | 0.3 µs |
| decode + verify a 100-entry, 4-agent transcript (363 KB) | 6.1 ms |
| peak RSS for the whole benchmark run (`/usr/bin/time -l`) | 5.8 MB |

## Size reference

| Item | Size |
|---|---|
| public key | 1952 B |
| signature | 3309 B |
| identity document | ≈ 5.4 KB |
| manifest | ≈ 3.4–4.4 KB |
