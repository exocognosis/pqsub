# Positioning: what pqsub is for

## The failure mode we actually address

An LLM agent that reads untrusted content can be prompt-injected into requesting a side effect nobody authorized: a payment to the wrong account, an email that leaks data, a write outside its directory. The question is whether that request can *succeed*, and whether anyone can later prove what happened.

Two common answers leave that open:

- **(a) Better prompts, filters and monitoring.** These lower the probability of a hijack. They cannot rule out an injected agent issuing an unauthorized request, because they act on the same text the attacker controls.
- **(b) Permission checks that run inside the agent.** Many agent stacks give the agent process the API credential and check a token, scope or allow-list in its own tool-calling layer before the call. If that process is compromised, the check is compromised with it. (Capability tokens verified at the resource server, such as macaroons or UCAN, avoid this; pqsub uses the same attenuation idea.)

pqsub starts from the opposite assumption: **treat the agent as fully compromised.** Authorization is enforced by a gate inside the *executor*, the component that holds the credential or performs the side effect. Every attempt, executed or refused, is recorded in a signed, hash-chained transcript that a third party can audit offline with one public key.

## What is proven today

Each item is backed by code, the independent verifier, published test vectors or a runnable example.

- **Signatures.** Identities, grants, tool calls and receipts are signed with ML-DSA-65 (FIPS 204). Two implementations on different ML-DSA libraries produce byte-identical keys and signatures on the test vectors.
- **Caveat evaluation.** Nine caveat types evaluate identically in both implementations on every vector and on fuzzed inputs; known bypass patterns are rejected.
- **Attenuation.** A delegated grant can only narrow its parent; widening attempts are rejected.
- **Transcript integrity.** Every single-bit flip in the exhaustively tested objects is detected, with identical error codes from both implementations.
- **Offline audit.** Given only the root public key, the audit distinguishes authorized executions, justified and unjustified refusals (`BLOCKED`), unanswered calls (`NO_RECEIPT`), and executions the gate should have refused (`EXECUTED_UNAUTHORIZED`).
- **Grant revocation (v2.1).** An issuer can revoke a grant in the transcript; it takes effect from its position in the hash chain, so it cannot be backdated.

## What is still assumed or future work

From [THREAT_MODEL.md](THREAT_MODEL.md) and [V2_DESIGN.md](V2_DESIGN.md):

- Tools are reachable **only** through executors that run the gate, and only executors hold tool credentials. A dishonest executor is not prevented; it is caught by the audit.
- Executors use their own clock and ingest revocations before appending later receipts.
- Agent keys and identity documents cannot be revoked; the offline root cannot revoke its own grant. There is no transparency log yet.
- Transcripts are not confidential. Keys are stored locally, unencrypted at rest.
- Grants bound authority; they do not make behaviour inside that authority correct. Policy quality is the operator's job.
- The independent verifier was written by another instance of the same model from the same spec, so a shared misreading of the spec is not ruled out.

## Concrete next integrations

1. **MCP proxy.** A gate that sits in front of an MCP tool server, speaks its JSON-RPC, and holds the server's credentials.
2. **HTTP tool-server wrapper.** The gate as middleware for an HTTP tool endpoint, wrapping the call shown in [`gated_tool.rs`](../crates/pqsub-cli/examples/gated_tool.rs).
3. **Reference payment gate.** A payment executor (including HTTP-402 / x402-style flows) that enforces payee, amount and budget caveats before signing a payment.
4. **Framework adapter notes.** Short recipes for routing tool calls from common agent SDKs through a remote gate instead of calling tools in-process.

## The claim

If tools are reachable only through executors that run the gate, then a prompt-injected agent cannot cause a side effect outside the authority delegated to it, and a third party can verify this from the transcript.
