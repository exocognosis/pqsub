# pqsub design note (format v1)

This document is the **normative spec**. `pqsub-verify` was written against it, not against `pqsub-core`.

## 1. Primitives

| Purpose | Primitive |
|---|---|
| Signatures | ML-DSA-65, FIPS 204, *pure* mode (no pre-hash), with a context string |
| Hashing | SHA3-256 (FIPS 202) |
| Secret key at rest | 32-byte FIPS 204 seed `ξ`. The expanded key comes from `ML-DSA.KeyGen_internal` |
| Signing randomness | Hedged: `rnd` comes from the OS CSPRNG (default). Deterministic: `rnd = 0^32`, used for tests and vectors |

Domain-separated hash: `H_d(x) = SHA3-256( u8(len(d)) ‖ d ‖ x )`.

| Name | Domain / context `d` | Applied to |
|---|---|---|
| AgentId | `pqsub/v1/agent-id` | the 1952-byte encoded ML-DSA-65 public key |
| Entry hash | `pqsub/v1/entry` | manifest **body** bytes (not the signature) |
| Payload hash | `pqsub/v1/payload` | arbitrary out-of-band payload bytes |
| ML-DSA ctx (identity) | `pqsub/v1/identity` | — |
| ML-DSA ctx (manifest) | `pqsub/v1/manifest` | — |

The entry hash covers the body only. A second valid signature over the same body therefore cannot change the chain.

## 2. Encodings

The encodings are canonical: integers are big-endian, strings are UTF-8 with a fixed-width length prefix, and there are no optional encodings. A decoder MUST reject:
- bad magic or version
- unknown enum values
- lengths out of range
- invalid UTF-8
- truncation
- trailing bytes

Because of these rules every value has exactly one byte encoding. Signatures are verified over the exact received body bytes.

### 2.1 Public key file (`*.pub`)
```
"PQSP" | 0x01 | pk[1952]
```

### 2.2 Secret key file (`*.key`, mode 0600)
```
"PQSK" | 0x01 | seed[32] | agent_id[32]
```
On load the keypair is re-derived from `seed`, and `agent_id` must match.

### 2.3 Identity document (`*.id`)
```
body = "PQSI" | 0x01
     | agent_id[32]
     | public_key[1952]
     | u8 n | name[n]        1 ≤ n ≤ 64
     | u8 n | role[n]        1 ≤ n ≤ 64
     | not_before_ms u64 | not_after_ms u64      (not_before ≤ not_after, else reject)
     | issuer_id[32]
doc  = body | sig[3309]       sig = ML-DSA-65.Sign(issuer_sk, body, ctx="pqsub/v1/identity")
```

### 2.4 Manifest (`*.pqsm`)
```
body = "PQSM" | 0x01
     | kind u8               1 handoff · 2 tool-authorization · 3 action-record
     | sender[32]            AgentId of the signer
     | recipient             0x01 | agent_id[32]
                           | 0x02 | u8 n | role[n]      1 ≤ n ≤ 64
     | seq u64               per-sender, strictly increasing within a trace
     | timestamp_ms u64      sender-asserted
     | prev[32]              entry hash of previous trace entry; 0^32 at genesis / standalone
     | u16 n | intent[n]     1 ≤ n ≤ 1024
     | 0x00                  no payload
     | 0x01 | payload_hash[32]
manifest = body | sig[3309]  sig = ML-DSA-65.Sign(sender_sk, body, ctx="pqsub/v1/manifest")
```
The body alone is self-delimiting. A decoder parses it and then expects exactly 3309 signature bytes and end of input.

Typical size: about 3.5 KB, of which 3309 bytes are the signature.

### 2.5 Transcript (`*.pqst`)
```
"PQST" | 0x01
| u16 n_ids    (≤ 1024)    | { u32 len (1..=16384) | identity_doc[len] }*
| u32 n_entries (≤ 2^20)   | { u32 len (1..=16384) | manifest[len] }*
```
Each item must decode exactly to its `len`.

**The root public key is not in the transcript.** The verifier must get it out of band.

## 3. Verification algorithm

Inputs:
- `root_pk`
- transcript bytes
- `from`
- `anchor`, one of:
  - `genesis`
  - `hash(h)`
  - `none`
- optional `expected_head`

The checks run in this order. The first failure is reported with its code, and both implementations follow the same order.

1. Decode the whole container strictly, then take the window `entries[from..]` → `DECODE`.
2. For each identity document, in order:
   1. `issuer_id == AgentId(root_pk)` → `IDENTITY_INVALID`
   2. The ML-DSA signature over the body verifies under `root_pk` with ctx `pqsub/v1/identity` → `IDENTITY_INVALID`
   3. `agent_id == AgentId(public_key)` → `IDENTITY_INVALID`
   4. The agent id has not been seen before → `DUPLICATE_IDENTITY`
3. Set `expected_prev`:
   - `0^32` for genesis
   - `h` for `hash(h)`
   - unset for `none`
4. For each window entry `i`:
   1. If `expected_prev` is set, `prev == expected_prev` → `CHAIN_BROKEN`
   2. The sender has a verified identity → `UNKNOWN_SENDER`
   3. The ML-DSA signature over the body verifies under the sender's key with ctx `pqsub/v1/manifest` → `BAD_SIGNATURE`
   4. `not_before ≤ timestamp_ms ≤ not_after` → `IDENTITY_EXPIRED`
   5. `seq` is greater than this sender's previous `seq` in the window → `SEQ_REPLAY`
   6. Set `expected_prev = H_entry(body)`
5. `head` is the last entry hash. If the window is empty, it is the anchor, or zero. If `expected_head` is given, `head == expected_head` → `HEAD_MISMATCH`.

Standalone handoff (`verify_handoff`) runs these checks:
1. Identity checks as in step 2.
2. `sender == identity.agent_id` → `UNKNOWN_SENDER`
3. Signature → `BAD_SIGNATURE`
4. Validity window → `IDENTITY_EXPIRED`

Constant-time comparisons (`subtle`) are used for every id and hash equality on these paths. The compared values are public, so this is defence in depth.

## 4. Crates

| Crate | Role | ML-DSA backend |
|---|---|---|
| `pqsub-core` | Library: keys, identity, manifest, trace, keystore | RustCrypto `ml-dsa =0.1.2` |
| `pqsub-cli` | `pqsub` binary, simulation, vector generator, benchmarks | (via core) |
| `pqsub-verify` | Independent verifier, library and binary. It does not link `pqsub-core`, which is only a dev-dependency for cross-tests | IntegrityChain `fips204 =0.5.0` |

## 5. Evidence that the two implementations agree

- `test-vectors/vectors.json` contains:
  - 25 transcript cases: 4 valid and 21 invalid, covering every error code
  - 4 key-generation vectors
  - 2 signature vectors (`rnd` = 0 and `rnd` = `0x42…`)
- Each case records its *intended* verdict. The generator refuses to emit a case if core disagrees. A test fails if the committed file drifts from regeneration.
- `fips204` key generation from the same seed gives byte-identical public keys. Its signatures, for the same `rnd`, are byte-identical to `ml-dsa`'s.
- Bit flips over a 1-identity, 1-entry transcript (≈ 29k flips):
  - Every bit of the manifest is flipped.
  - Every 29th bit of the identity and container is flipped.
  - Every flip is rejected by both implementations with **identical error codes**.
- 400 random mutations (byte overwrite, truncation, insertion, deletion) produce identical verdicts and codes.

## 6. Known limitations (format level)

- No revocation, key rotation or multi-root. One root key signs every identity.
- `timestamp_ms` is asserted by the sender. Validity windows are only as trustworthy as the sender's clock and honesty.
- Sequence numbers are checked only inside the verified window. Standalone handoffs get no cross-message replay protection unless the receiver tracks `(sender, seq)`.
- There is no recipient acknowledgement. A manifest proves who *sent* what, not that it was received or acted on.
- A sender can sign two different continuations from the same `prev` (fork / equivocation). This is detectable only if a verifier sees both, or pins heads externally.
- There is no format negotiation. A future v2 would use a new version byte and new context and domain strings.
