# Threat model

## System and trust boundaries

```
 operator ──(root key, offline-ish)──► issues identity docs
                                            │
 agent A ──signs manifest──►  transport / storage / orchestrator  ──► agent B
   (own key, 0600 file)        (UNTRUSTED: may drop, reorder,           │
                                 modify, replay, inject)                 ▼
                                            │                      third-party auditor
                                            └──── transcript ────►  (has root.pub out of band,
                                                                     runs pqsub-verify)
```

| Boundary | Trusted? |
|---|---|
| Root public key, as obtained by the verifier out of band | **Yes**. This is the single trust anchor |
| Root secret key | Trusted to issue only correct identities |
| Each agent's secret key and the process holding it | Trusted to sign only what that agent intends |
| Transport, message bus, orchestrator, storage, the transcript file | **Untrusted** |
| The agent that produced a transcript | **Untrusted** by the verifier |
| Clocks | Untrusted for ordering; trusted only as the sender's assertion |

## Adversary

The adversary controls every channel and every storage location. They can read, drop, reorder, replay, truncate, splice and modify bytes. They can create their own ML-DSA keys and their own "root". They may hold a large-scale quantum computer. That breaks ECDSA/Ed25519/RSA, and ML-DSA-65 is designed to resist it (NIST category 3).

## What is protected

1. **Authenticity and integrity of every manifest.** Changing any body or signature bit invalidates it. The tests check this exhaustively for single-bit flips in both implementations.
2. **Binding of an agent id to a key and claims.** An identity is accepted only if the configured root signed it **and** `agent_id = H(pk)`.
3. **Sender binding.** A manifest verifies only under the key whose hash is its `sender` field. Re-attributing a manifest to another agent fails.
4. **Domain separation.** Identity and manifest signatures use distinct ML-DSA context strings, so one cannot be passed off as the other. Hashes use distinct domains.
5. **Trace integrity.** Hash chaining over bodies detects:
   - reordering
   - deletion
   - insertion
   - substitution
   - duplication of entries
   - splicing of entries from another trace

   Within the verified window, a per-sender `seq` replay is detected.
6. **Prefix and tail truncation, when pinned.** A suffix anchored at a known checkpoint, or a trace checked against a known head, detects truncation at either end.
7. **Third-party verifiability.** The auditor needs only `root.pub` plus the transcript. It does not trust the producing agent or the `pqsub-core` code: `pqsub-verify` is an independent implementation on a different ML-DSA library.
8. **Post-quantum security** of signatures, under the ML-DSA-65 hardness assumptions (MLWE/MSIS). SHA3-256 gives about 128-bit collision resistance against quantum attackers.

## What is NOT protected

- **A compromised agent key.** The holder can sign anything as that agent. **Expiry does not limit this**: validity is checked against the sender-asserted `timestamp_ms`, so a key holder can backdate manifests into the window and they verify indefinitely. Only revocation (not implemented), trusted external time, or pinning trace heads before the compromise would bound it.
- **A compromised root key.** The holder can mint arbitrary identities. Keep it off agent hosts. `pqsub` stores it like any other key, so separating it is an operational responsibility.
- **Semantic safety of `intent` or payloads.** A valid signature shows that *agent X said this*, not that it is safe or true. Intent text from another agent is untrusted input, for example a prompt-injection vector, and must still pass policy.
- **Confidentiality.** Nothing is encrypted. Manifests, intents and identities are plaintext. Payloads appear only as hashes, but intents are visible.
- **Freshness and replay of standalone handoffs.** Receivers must track `(sender, seq)` themselves. Timestamps are sender-asserted.
- **Unanchored suffixes.** With `--anchor none`, a dropped prefix is undetectable. Without `--expect-head`, a dropped tail is undetectable.
- **Equivocation.** A sender can produce two forks from the same point. Detecting this needs heads to be published or witnessed.
- **Availability.** An adversary can always drop messages.
- **Receipt or execution.** There is no proof that a recipient received or acted on a manifest. An `action-record` is a claim made by the actor.
- **Cross-recipient replay.** Verification never checks the recipient. A handoff addressed to Bob verifies just as well when replayed to Carol, so receivers must check that `recipient` is themselves (or their role) and track `(sender, seq)`.

## Key handling assumptions

- Secret keys are 32-byte seeds in `*.key` files with these protections:
  - mode `0600`, inside a `0700` directory
  - created with `O_EXCL`
  - written to a temporary file and renamed into place
  - never overwritten
- Loading refuses group- or world-accessible files and symlinks.
- **Keys are not encrypted at rest.** Anyone with the user's file access, backups or root access gets the keys. A production system would use the macOS Keychain or Secure Enclave wrapping, an HSM or a KMS. The `KeyStore` trait is the extension point.
- Seeds and in-memory keys are zeroized on drop (`zeroize`). The RustCrypto `ml-dsa` `SigningKey` implements `ZeroizeOnDrop`. Copies made by the OS, such as swap or core dumps, are out of scope.
- Hedged signing draws `rnd` from `getrandom` (macOS `getentropy`).

## Implementation caveats

- `ml-dsa` 0.1.x and `fips204` 0.5.x are pure-Rust, KAT-tested implementations. Neither has had an independent third-party audit, and both pre-date 1.0. Cross-implementation agreement reduces the risk of a single-implementation bug but does not replace an audit.
- **Panics in the signer.** `ml-dsa`'s `sign_internal` and `sign_deterministic` can panic if the FIPS 204 rejection-sampling loop exceeds its bound, which has negligible probability. pqsub's own code paths do not panic.
- **Side channels.** Signing is the only operation that touches secrets. Its constant-time behaviour is inherited from `ml-dsa`. Note that the FIPS 204 rejection loop leaks only the iteration count, which is public by design. Timing, cache and power behaviour on Apple M4 has not been measured. Verification handles only public data.
- **Denial of service.** Decoders enforce size limits:
  - each item ≤ 16 KiB
  - ≤ 1024 identities
  - ≤ 2^20 entries

  Allocation is incremental, but a 2^20-entry transcript is still about 3.6 GB. Callers should bound input size before decoding.
- **Key store race.** `FileKeyStore::save` re-checks for an existing file before renaming, which narrows but does not eliminate a race with a concurrent writer.
- No formal verification was done; that is out of scope.

## v2: delegated authority (P1)

v2 adds grants, tool calls checked by a gate, receipts and an audit. The full trust boundary, assumptions A1–A3, the exact claim and its limits are in [V2_DESIGN.md §1 and §13](V2_DESIGN.md).

**New trusted components.** The executor and its gate are part of the trusted computing base:
- A malicious executor can lie in its receipts.
- An executor that runs a call anyway is caught by the audit as `EXECUTED_UNAUTHORIZED`, but only after the fact.
- Tool credentials must exist only inside the executor.

**Time.** Authorization is checked against the executor's clock: live, and through the receipt timestamp during audit. The caller's timestamp is never used. This fixes the v1 backdating issue for tool calls. It does not fix it for plain v1 handoffs.

**Grant scope.** Grants bound authority; they do not make agent behaviour correct. An injected agent can still do anything its grant permits, so tight caveats and task-scoped grants are the defence.

**Open issues:**
- revocation (planned for P4 via a transparency log)
- expiry of an issuer identity does not invalidate the grants it issued
- budgets are sound only with one gate per executor role
