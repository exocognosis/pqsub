//! Authorization check (V2_DESIGN §14.8) and offline audit (§14.10), with
//! grant revocation (§14.13, v2.1).

use std::collections::{HashMap, HashSet};

use crate::caveat::{ExecCtx, Kind};
use crate::cjson::Value;
use crate::grant::Grant;
use crate::{
    check_root_len, ct, decode_transcript, fail, hd, mldsa_verify, verify_decoded, Anchor, Ext,
    Failure, Ident, Recipient, Report, CTX_GRANT, D_AGENT_ID, H32,
};

/// Gate / audit reason numbers (§7.1, §14.8).
pub mod reason {
    /// Chain id does not resolve.
    pub const GRANT_UNKNOWN: u8 = 2;
    /// Grant signature invalid.
    pub const GRANT_INVALID: u8 = 3;
    /// Chain rules violated.
    pub const GRANT_CHAIN: u8 = 4;
    /// `t` outside a grant's validity window.
    pub const GRANT_EXPIRED: u8 = 5;
    /// A caveat does not hold.
    pub const CAVEAT_VIOLATION: u8 = 6;
    /// A `MaxCalls` budget would be exceeded.
    pub const BUDGET_EXCEEDED: u8 = 7;
    /// A grant in the chain is revoked for the call (§14.13, step 4a).
    pub const GRANT_REVOKED: u8 = 9;
}

/// One audit finding (§14.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// `EXECUTED_UNAUTHORIZED`, `BLOCKED` or `NO_RECEIPT`.
    pub code: &'static str,
    /// Window index of the receipt (or of the call, for `NO_RECEIPT`).
    pub index: usize,
    /// Window index of the tool call.
    pub call_index: usize,
    /// Reason number (inner failure, receipt reason, or 0).
    pub reason: u8,
    /// For `BLOCKED`: whether the refusal was justified. Otherwise false.
    pub justified: bool,
}

/// Successful audit result.
#[derive(Debug, Clone)]
pub struct AuditReport {
    /// The v1 verification report.
    pub report: Report,
    /// Findings in receipt order, then `NO_RECEIPT` in call order.
    pub findings: Vec<Finding>,
}

impl AuditReport {
    /// True iff no `EXECUTED_UNAUTHORIZED` finding exists (`--require-authorized`).
    #[must_use]
    pub fn all_authorized(&self) -> bool {
        !self
            .findings
            .iter()
            .any(|f| f.code == "EXECUTED_UNAUTHORIZED")
    }
}

type Counters = HashMap<(H32, usize), u64>;

/// Accepted revocations as `(revoker agent id, target grant id)` (§14.13 item 3).
type Revocations = HashSet<(H32, H32)>;

/// §14.13 item 3: `chain[k]` is revoked for the call iff some accepted
/// revocation targets `id(chain[k])` and was sent by the issuer of `chain[j]`
/// for some `j <= k` (the grant's own issuer or the issuer of an ancestor in
/// this call's chain). Revocations by anyone else, or of grants outside the
/// chain, have no effect.
fn chain_revoked(gs: &[&Grant<'_>], revoked: &Revocations) -> bool {
    if revoked.is_empty() {
        return false;
    }
    gs.iter().enumerate().any(|(k, g)| {
        gs.iter()
            .take(k.saturating_add(1))
            .any(|anc| revoked.contains(&(anc.issuer, g.id)))
    })
}

struct Ctx<'a> {
    root_pk: &'a [u8],
    root_id: H32,
    grants: &'a HashMap<H32, &'a Grant<'a>>,
    idents: &'a HashMap<H32, &'a Ident<'a>>,
}

struct Call<'a> {
    sender: &'a H32,
    recipient: &'a Recipient,
    tool: &'a str,
    args: &'a Value,
    chain: &'a [H32],
}

/// §14.8 (+ step 4a of §14.13). Returns the failing reason number. Counters
/// are incremented only on success and only when `commit`.
fn authorize(
    cx: &Ctx<'_>,
    call: &Call<'_>,
    t: u64,
    executor: &Ident<'_>,
    revoked: &Revocations,
    counts: &mut Counters,
    commit: bool,
) -> Result<(), u8> {
    // 1. GRANT_UNKNOWN
    let mut gs: Vec<&Grant<'_>> = Vec::with_capacity(call.chain.len());
    for id in call.chain {
        gs.push(cx.grants.get(id).copied().ok_or(reason::GRANT_UNKNOWN)?);
    }
    // 2. GRANT_INVALID
    for g in &gs {
        let key: &[u8] = if ct(&g.issuer, &cx.root_id) {
            cx.root_pk
        } else {
            cx.idents
                .get(&g.issuer)
                .map(|d| d.pk)
                .ok_or(reason::GRANT_INVALID)?
        };
        if !mldsa_verify(key, g.body, CTX_GRANT, g.sig) {
            return Err(reason::GRANT_INVALID);
        }
    }
    // 3. GRANT_CHAIN
    let (Some(first), Some(leaf)) = (gs.first(), gs.last()) else {
        return Err(reason::GRANT_CHAIN);
    };
    if !(ct(&first.issuer, &cx.root_id) && ct(&first.parent, &[0u8; 32])) {
        return Err(reason::GRANT_CHAIN);
    }
    for w in gs.windows(2) {
        let [prev, g] = w else {
            return Err(reason::GRANT_CHAIN);
        };
        if !(ct(&g.parent, &prev.id) && ct(&g.issuer, &prev.audience) && g.depth < prev.depth) {
            return Err(reason::GRANT_CHAIN);
        }
    }
    if !ct(&leaf.audience, call.sender) {
        return Err(reason::GRANT_CHAIN);
    }
    // 4. GRANT_EXPIRED
    if gs.iter().any(|g| t < g.nb || t > g.na) {
        return Err(reason::GRANT_EXPIRED);
    }
    // 4a. GRANT_REVOKED (§14.13), after steps 1-4 have covered the whole chain.
    if chain_revoked(&gs, revoked) {
        return Err(reason::GRANT_REVOKED);
    }
    // 5. CAVEAT_VIOLATION
    let exec = ExecCtx {
        recipient: call.recipient,
        executor_role: &executor.role,
    };
    for g in &gs {
        for cv in &g.caveats {
            if cv.scope_matches(call.tool)
                && !matches!(cv.kind, Kind::MaxCalls(_))
                && !cv.holds(call.tool, Some(call.args), Some(&exec))
            {
                return Err(reason::CAVEAT_VIOLATION);
            }
        }
    }
    // 6. BUDGET_EXCEEDED
    let mut budget_keys = Vec::new();
    for g in &gs {
        for (j, cv) in g.caveats.iter().enumerate() {
            if let Kind::MaxCalls(n) = cv.kind {
                if cv.scope_matches(call.tool) {
                    let used = counts.get(&(g.id, j)).copied().unwrap_or(0);
                    if used.saturating_add(1) > u64::from(n) {
                        return Err(reason::BUDGET_EXCEEDED);
                    }
                    budget_keys.push((g.id, j));
                }
            }
        }
    }
    // 7. Success.
    if commit {
        for k in budget_keys {
            let e = counts.entry(k).or_insert(0);
            *e = e.saturating_add(1);
        }
    }
    Ok(())
}

/// Full v2 audit (§14.10): v1 trace verification, then receipt checks and
/// authorization findings. Works on v1 transcripts too (no findings).
///
/// # Errors
/// The v1 failure code, or a fatal audit code (`RECEIPT_ORPHAN`,
/// `DUPLICATE_RECEIPT`, `RECEIPT_WRONG_EXECUTOR`).
pub fn audit_transcript(
    root_pk: &[u8],
    transcript: &[u8],
    from: usize,
    anchor: Anchor,
    expected_head: Option<[u8; 32]>,
) -> Result<AuditReport, Failure> {
    check_root_len(root_pk)?;
    let decoded = decode_transcript(transcript)?;
    let (report, parsed) = verify_decoded(root_pk, &decoded, from, anchor, expected_head)?;
    let cx = Ctx {
        root_pk,
        root_id: hd(D_AGENT_ID, root_pk),
        grants: &parsed.grants,
        idents: &parsed.idents,
    };
    let window = parsed.window;
    let mut calls: HashMap<H32, usize> = HashMap::new();
    let mut call_order: Vec<usize> = Vec::new();
    let mut receipted: HashSet<usize> = HashSet::new();
    let mut counts = Counters::new();
    // §14.13 items 6-7: only kind-6 entries inside the window, and only those
    // at indices below the receipt's index, are applied. Walking in order and
    // inserting on arrival gives exactly that set at each receipt.
    let mut revoked = Revocations::new();
    let mut findings = Vec::new();

    for (i, e) in window.iter().enumerate() {
        let Some(h) = report.entry_hashes.get(i) else {
            return fail("DECODE", "internal: entry hash missing");
        };
        match &e.ext {
            Ext::Call { .. } => {
                calls.insert(*h, i);
                call_order.push(i);
            }
            Ext::Receipt {
                call_ref,
                status,
                reason: r_reason,
            } => {
                let Some(&ci) = calls.get(call_ref) else {
                    return fail("RECEIPT_ORPHAN", format!("entry {i}"));
                };
                if !receipted.insert(ci) {
                    return fail("DUPLICATE_RECEIPT", format!("entry {i} (call {ci})"));
                }
                let (Some(c), Some(executor)) = (window.get(ci), parsed.idents.get(&e.sender))
                else {
                    return fail("UNKNOWN_SENDER", format!("entry {i}"));
                };
                let wrong = match &c.recipient {
                    Recipient::Agent(id) => !ct(&e.sender, id),
                    Recipient::Role(r) => executor.role != *r,
                };
                if wrong {
                    return fail("RECEIPT_WRONG_EXECUTOR", format!("entry {i} (call {ci})"));
                }
                let Ext::Call { tool, args, chain } = &c.ext else {
                    return fail("RECEIPT_ORPHAN", format!("entry {i}"));
                };
                let call = Call {
                    sender: &c.sender,
                    recipient: &c.recipient,
                    tool,
                    args,
                    chain,
                };
                if *status == 2 {
                    let res = authorize(&cx, &call, e.ts, executor, &revoked, &mut counts, false);
                    findings.push(Finding {
                        code: "BLOCKED",
                        index: i,
                        call_index: ci,
                        reason: *r_reason,
                        justified: res.is_err(),
                    });
                } else if let Err(r) =
                    authorize(&cx, &call, e.ts, executor, &revoked, &mut counts, true)
                {
                    findings.push(Finding {
                        code: "EXECUTED_UNAUTHORIZED",
                        index: i,
                        call_index: ci,
                        reason: r,
                        justified: false,
                    });
                }
            }
            // §14.13 item 6: no finding of its own; the sender passed all v1
            // checks, and entitlement is evaluated per call.
            Ext::Revocation { target } => {
                revoked.insert((e.sender, *target));
            }
            Ext::None => {}
        }
    }
    for ci in call_order {
        if !receipted.contains(&ci) {
            findings.push(Finding {
                code: "NO_RECEIPT",
                index: ci,
                call_index: ci,
                reason: 0,
                justified: false,
            });
        }
    }
    Ok(AuditReport { report, findings })
}
