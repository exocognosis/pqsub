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
test-vectors/         vectors.json (v1: 25 transcript cases + keygen/signature) · vectors-v2.json (48 cjson, 62 caveat, 25 audit cases)
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

The full test suite takes about 90 s on the development machine (MacBook Air, Apple M3, 16 GB). Most of that time goes to the exhaustive cross-implementation bit-flip test. Dependencies are built with `opt-level=3` even in the test profile, because unoptimized ML-DSA is much slower.

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

## v2 (phase P1): bounded, auditable agent authority

The full spec is in [docs/V2_DESIGN.md](docs/V2_DESIGN.md); its §14 is normative.

v1 proves **who said what**. v2 adds **who was allowed to do it** and **what actually executed**:

- **Grants.** These are signed delegation tokens. The root key, kept offline, issues one broad grant to a principal. The principal issues short-lived grants per task, and every further delegation can only narrow authority.
- **Caveats.** A grant restricts what its holder can do using a small fixed set of caveats:
  - a tool allow-list
  - equal-to and one-of checks on arguments
  - integer ranges
  - boundary-aware matchers for file paths, URL origins and email domains
  - call budgets
  - executor roles

  Any caveat whose argument is missing fails.
- **Tool calls.** Each tool call carries its arguments in a canonical JSON form, along with its chain of grants.
- **The gate.** It runs inside the tool executor and decides before anything runs, using the executor's own clock and counters. It signs a **receipt** either way: executed, or refused with a reason.
- **`pqsub audit` and `pqsub-verify audit`.** These verify integrity, then re-check every executed call at the time on its receipt. They report:
  - `BLOCKED`
  - `EXECUTED_UNAUTHORIZED`
  - `NO_RECEIPT`

  With `--require-authorized`, the audit exits with status 2 if any executed call was unauthorized.

```bash
pqsub audit --root root.pub transcript.pqst --require-authorized
pqsub-verify audit --root root.pub transcript.pqst --require-authorized   # independent implementation
pqsub-verify vectors-v2 test-vectors/vectors-v2.json
```

**Claim.** If tools can only be reached through executors that run the gate, then a prompt-injected agent cannot cause a side effect outside the authority delegated to it for the task. A third party can verify this from the transcript.

**What v2 does not cover:**
- harmful actions that stay *within* the granted authority
- information-flow control
- confidentiality
- revocation
- policy quality: a grant is only as good as its caveats

See V2_DESIGN §1 and §13.

**How independence was established, and its limits.** A separate agent built the v2 verifier from the spec alone and reports that it never read the core code. That agent was another instance of the same model, working from a spec written by the author of the core. Independence therefore lowers the risk of implementation bugs, but it does not rule out a misreading of the spec that both share. On first contact, the two implementations agreed on all 149 v2 vector checks. Differential tests then compared both implementations' error codes and exact audit findings:
- every bit flip in a grant body (2,304 flips, all detected)
- strided bit flips and random mutations of a full audit transcript
- every window offset of every vector
- 120k fuzzed canonical-JSON checks
- 20k fuzzed caveat checks

## Evidence

| Check | Result |
|---|---|
| `pqsub-core` v1 tests | 25 pass. Includes an exhaustive single-bit flip over all ≈ 28k bits of a manifest, and tamper/reorder/drop/truncate/replay/expiry/identity cases |
| `pqsub-core` v2 tests | 9 pass: canonical JSON, matcher bypass attempts, grant attenuation and chain rules, gate decisions, audit findings, v2 canonical rules |
| Cross-implementation, v1 | 5 pass:<br>• byte-identical keygen and signatures<br>• ≈ 29k bit flips get identical error codes from both<br>• 400 random mutations agree |
| Cross-implementation, v2 | 6 pass:<br>• all 2,304 bit flips of a grant body detected, with identical outcomes<br>• strided flips and mutations of a full audit transcript<br>• every window offset of every vector<br>• 120k fuzzed cjson and 20k fuzzed caveat checks<br>• `pqsub-verify audit` binary output matches the core library |
| `pqsub-verify` v2 unit tests | 16 pass |
| CLI end-to-end and reproducibility | 7 pass:<br>• committed v1 and v2 vectors match regeneration<br>• the demo transcript is byte-reproducible<br>• the full CLI workflow passes, including tamper, wrong root and payload mismatch<br>• `pqsub audit` binary output matches the independent library |
| `pqsub-verify vectors` / `vectors-v2` | `ALL VECTORS PASS` (37 v1 checks, 149 v2 checks) |

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
