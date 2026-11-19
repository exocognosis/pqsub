//! Authorization: the shared check (V2_DESIGN §14.8), the online [`Gate`]
//! (§14.9) and the offline [`audit`] (§14.10).

use std::collections::HashMap;

use crate::caveat::CaveatKind;
use crate::cjson;
use crate::error::{Error, Result};
use crate::grant::Grant;
use crate::hash::{payload_hash, AgentId, Hash32};
use crate::identity::IdentityDocument;
use crate::keys::{AgentKeypair, PublicKey};
use crate::manifest::{Ext, ManifestKind, Receipt, ReceiptStatus, Recipient, SignedManifest};
use crate::trace::{TraceReport, Transcript, VerifyOptions};

/// Why a tool call was not authorized. The number is the receipt `reason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Denial {
    /// Call not addressed to this executor (never recorded in a receipt).
    WrongExecutor = 1,
    /// A chain grant id is unknown.
    GrantUnknown = 2,
    /// A grant signature does not verify under its issuer's key.
    GrantInvalid = 3,
    /// Chain linkage / root / depth / audience rule violated.
    GrantChain = 4,
    /// Check time outside a grant's validity window.
    GrantExpired = 5,
    /// A caveat does not hold.
    CaveatViolation = 6,
    /// A `MaxCalls` budget would be exceeded.
    BudgetExceeded = 7,
    /// The call itself failed v1 checks at the gate (identity, signature, seq, kind).
    CallInvalid = 8,
    /// v2.1: a chain grant was revoked by an entitled revoker (§14.13).
    GrantRevoked = 9,
}

impl Denial {
    /// Stable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::WrongExecutor => "WRONG_EXECUTOR",
            Self::GrantUnknown => "GRANT_UNKNOWN",
            Self::GrantInvalid => "GRANT_INVALID",
            Self::GrantChain => "GRANT_CHAIN",
            Self::GrantExpired => "GRANT_EXPIRED",
            Self::CaveatViolation => "CAVEAT_VIOLATION",
            Self::BudgetExceeded => "BUDGET_EXCEEDED",
            Self::CallInvalid => "CALL_INVALID",
            Self::GrantRevoked => "GRANT_REVOKED",
        }
    }
}

/// Budget counters keyed by `(grant id, caveat index)`.
pub type Counters = HashMap<(Hash32, usize), u32>;

/// Inputs shared by gate and audit.
pub struct AuthzContext<'a> {
    /// Trust anchor.
    pub root: &'a PublicKey,
    /// Verified identities by agent id.
    pub identities: &'a HashMap<AgentId, &'a IdentityDocument>,
    /// Known grants by id.
    pub grants: &'a HashMap<Hash32, &'a Grant>,
    /// Accepted revocations as `(revoker, revoked grant id)` (§14.13).
    pub revocations: &'a [(AgentId, Hash32)],
}

/// §14.8 authorization check for tool call `call` at time `t`, executed by an
/// executor holding `executor_role`. On success returns the budget counter keys
/// to increment.
///
/// # Errors
/// The first failing [`Denial`] (reasons 2..=7, 9).
pub fn check_authorization(
    ctx: &AuthzContext<'_>,
    call: &SignedManifest,
    t: u64,
    executor_role: &str,
    counters: &Counters,
) -> core::result::Result<Vec<(Hash32, usize)>, Denial> {
    let tc = call.tool_call().ok_or(Denial::CallInvalid)?;
    let body = call.body();
    // (2) resolve
    let chain: Vec<&Grant> = tc
        .chain
        .iter()
        .map(|id| ctx.grants.get(id).copied().ok_or(Denial::GrantUnknown))
        .collect::<core::result::Result<_, _>>()?;
    // (3) signatures
    let root_id = ctx.root.agent_id();
    for g in &chain {
        let pk = if g.issuer().ct_eq(&root_id) {
            ctx.root
        } else {
            ctx.identities
                .get(&g.issuer())
                .ok_or(Denial::GrantInvalid)?
                .public_key()
        };
        if !g.verify_signature(pk) {
            return Err(Denial::GrantInvalid);
        }
    }
    // (4) chain rules
    let first = chain.first().ok_or(Denial::GrantChain)?;
    if !first.issuer().ct_eq(&root_id) || !first.spec().parent.ct_eq(&Hash32::ZERO) {
        return Err(Denial::GrantChain);
    }
    for w in chain.windows(2) {
        let (p, c) = (w[0], w[1]);
        if !c.spec().parent.ct_eq(&p.id())
            || !c.issuer().ct_eq(&p.spec().audience)
            || c.spec().depth >= p.spec().depth
        {
            return Err(Denial::GrantChain);
        }
    }
    let leaf = chain.last().ok_or(Denial::GrantChain)?;
    if !leaf.spec().audience.ct_eq(&body.sender) {
        return Err(Denial::GrantChain);
    }
    // (5) windows
    if chain.iter().any(|g| !g.is_valid_at(t)) {
        return Err(Denial::GrantExpired);
    }
    // (4a, §14.13) revocation by the grant's issuer or an ancestor's issuer in this chain
    for (k, g) in chain.iter().enumerate() {
        let revoked = ctx.revocations.iter().any(|(by, target)| {
            target.ct_eq(&g.id()) && chain[..=k].iter().any(|a| a.issuer().ct_eq(by))
        });
        if revoked {
            return Err(Denial::GrantRevoked);
        }
    }
    // (6) caveats
    let args = cjson::parse_canonical(&tc.args, true).map_err(|_| Denial::CallInvalid)?;
    for g in &chain {
        for c in &g.spec().caveats {
            if !c.holds(&tc.tool, &args, &body.recipient, executor_role) {
                return Err(Denial::CaveatViolation);
            }
        }
    }
    // (7) budgets
    let mut bump = Vec::new();
    for g in &chain {
        for (j, c) in g.spec().caveats.iter().enumerate() {
            if let CaveatKind::MaxCalls(n) = c.kind {
                if c.applies_to(&tc.tool) {
                    let used = counters.get(&(g.id(), j)).copied().unwrap_or(0);
                    if used.saturating_add(1) > n {
                        return Err(Denial::BudgetExceeded);
                    }
                    bump.push((g.id(), j));
                }
            }
        }
    }
    Ok(bump)
}

fn apply(counters: &mut Counters, bump: Vec<(Hash32, usize)>) {
    for k in bump {
        *counters.entry(k).or_insert(0) += 1;
    }
}

/// What the executor did with an allowed call.
#[derive(Clone, Copy, Debug)]
pub enum Outcome<'a> {
    /// Executed; tool returned `result` successfully.
    Ok(&'a [u8]),
    /// Executed; tool reported an error `result`.
    Error(&'a [u8]),
    /// Refused by the gate.
    Refused(Denial),
}

/// Build the receipt extension for `call` (append it to the trace with the
/// executor's key, kind [`ManifestKind::Receipt`]).
///
/// # Errors
/// [`Error::InvalidField`] for `Refused(WrongExecutor)`: such calls must be
/// rejected without a receipt.
pub fn receipt_ext(call: &SignedManifest, outcome: Outcome<'_>) -> Result<Ext> {
    let (status, reason, result_hash) = match outcome {
        Outcome::Ok(r) => (ReceiptStatus::ExecutedOk, 0, payload_hash(r)),
        Outcome::Error(r) => (ReceiptStatus::ExecutedError, 0, payload_hash(r)),
        Outcome::Refused(Denial::WrongExecutor) => {
            return Err(Error::InvalidField("wrong-executor calls get no receipt"))
        }
        Outcome::Refused(d) => (ReceiptStatus::Refused, d as u8, Hash32::ZERO),
    };
    Ok(Ext::Receipt(Receipt {
        call_ref: call.entry_hash(),
        status,
        reason,
        result_hash,
    }))
}

/// Online enforcement point, run inside the executor (the TCB).
pub struct Gate {
    root: PublicKey,
    key: AgentKeypair,
    role: String,
    identities: HashMap<AgentId, IdentityDocument>,
    grants: HashMap<Hash32, Grant>,
    last_seq: HashMap<AgentId, u64>,
    revocations: Vec<(AgentId, Hash32)>,
    counters: Counters,
}

impl Gate {
    /// Create a gate for executor `key`. Every identity is verified against
    /// `root`; the executor's own identity must be among them.
    ///
    /// # Errors
    /// Identity verification failures, or [`Error::InvalidField`] if the
    /// executor has no identity.
    pub fn new(
        root: PublicKey,
        key: AgentKeypair,
        identities: Vec<IdentityDocument>,
    ) -> Result<Self> {
        let mut map = HashMap::new();
        for d in identities {
            d.verify(&root)?;
            if map.insert(d.agent_id(), d).is_some() {
                return Err(Error::InvalidField("duplicate identity"));
            }
        }
        let role = map
            .get(&key.agent_id())
            .ok_or(Error::InvalidField("executor identity missing"))?
            .claims()
            .role
            .clone();
        Ok(Self {
            root,
            key,
            role,
            identities: map,
            grants: HashMap::new(),
            last_seq: HashMap::new(),
            revocations: Vec::new(),
            counters: Counters::new(),
        })
    }

    /// Register a grant (verified lazily when a call references it).
    pub fn add_grant(&mut self, g: Grant) {
        self.grants.insert(g.id(), g);
    }

    /// Accept a signed revocation (kind 6, §14.13). It takes effect for every
    /// later check. Whether the revoker is entitled is decided per call.
    ///
    /// # Errors
    /// [`Error::InvalidField`] if `rev` is not a revocation, its sender is not a
    /// known identity, or its signature does not verify.
    pub fn add_revocation(&mut self, rev: &SignedManifest) -> Result<()> {
        let target = rev
            .revocation()
            .ok_or(Error::InvalidField("not a revocation"))?;
        let by = rev.body().sender;
        let doc = self
            .identities
            .get(&by)
            .ok_or(Error::InvalidField("revoker identity unknown"))?;
        if !rev.signature_valid_under(doc.public_key()) {
            return Err(Error::InvalidField("revocation signature invalid"));
        }
        self.revocations.push((by, target));
        Ok(())
    }

    /// The executor's signing key (used to sign receipts).
    #[must_use]
    pub fn key(&self) -> &AgentKeypair {
        &self.key
    }

    /// Executor role.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Decide whether to execute `call` now (`now_ms` = executor clock).
    /// Allowed calls consume budget. The caller executes the tool only on `Ok`.
    ///
    /// # Errors
    /// The [`Denial`]. For [`Denial::WrongExecutor`] emit no receipt.
    pub fn check(
        &mut self,
        call: &SignedManifest,
        now_ms: u64,
    ) -> core::result::Result<(), Denial> {
        let b = call.body();
        if b.kind != ManifestKind::ToolCall {
            return Err(Denial::CallInvalid);
        }
        let doc = self.identities.get(&b.sender).ok_or(Denial::CallInvalid)?;
        if !call.signature_valid_under(doc.public_key()) || !doc.is_valid_at(now_ms) {
            return Err(Denial::CallInvalid);
        }
        if self.last_seq.get(&b.sender).is_some_and(|s| b.seq <= *s) {
            return Err(Denial::CallInvalid);
        }
        let mine = match &b.recipient {
            Recipient::Agent(id) => id.ct_eq(&self.key.agent_id()),
            Recipient::Role(r) => *r == self.role,
        };
        if !mine {
            return Err(Denial::WrongExecutor);
        }
        self.last_seq.insert(b.sender, b.seq);
        let ids: HashMap<AgentId, &IdentityDocument> =
            self.identities.iter().map(|(k, v)| (*k, v)).collect();
        let grants: HashMap<Hash32, &Grant> = self.grants.iter().map(|(k, v)| (*k, v)).collect();
        let ctx = AuthzContext {
            root: &self.root,
            identities: &ids,
            grants: &grants,
            revocations: &self.revocations,
        };
        let bump = check_authorization(&ctx, call, now_ms, &self.role, &self.counters)?;
        apply(&mut self.counters, bump);
        Ok(())
    }

    /// Check `call`, run `tool(args)` **only if** it is authorized, and return
    /// the receipt extension to sign into the transcript (kind
    /// [`ManifestKind::Receipt`], signed with [`Gate::key`]).
    ///
    /// `tool` returns `Ok(result)` or `Err(error_result)`; both are hashed into
    /// the receipt. This is the whole integration surface for wrapping a tool.
    ///
    /// # Errors
    /// `Err(Denial::WrongExecutor)` if the call is addressed to another
    /// executor: drop it, it gets no receipt. Every other denial is returned as
    /// an `Ok` refused receipt and the tool is not run.
    pub fn execute<F>(
        &mut self,
        call: &SignedManifest,
        now_ms: u64,
        tool: F,
    ) -> core::result::Result<Ext, Denial>
    where
        F: FnOnce(&[u8]) -> core::result::Result<Vec<u8>, Vec<u8>>,
    {
        let receipt = |status, reason, result_hash| {
            Ext::Receipt(Receipt {
                call_ref: call.entry_hash(),
                status,
                reason,
                result_hash,
            })
        };
        match self.check(call, now_ms) {
            Err(Denial::WrongExecutor) => Err(Denial::WrongExecutor),
            Err(d) => Ok(receipt(ReceiptStatus::Refused, d as u8, Hash32::ZERO)),
            Ok(()) => {
                let args = call.tool_call().map_or(&[][..], |c| &c.args[..]);
                Ok(match tool(args) {
                    Ok(r) => receipt(ReceiptStatus::ExecutedOk, 0, payload_hash(&r)),
                    Err(r) => receipt(ReceiptStatus::ExecutedError, 0, payload_hash(&r)),
                })
            }
        }
    }
}

/// An authorization finding from [`audit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// `EXECUTED_UNAUTHORIZED`, `BLOCKED` or `NO_RECEIPT`.
    pub code: &'static str,
    /// Window index of the receipt (or of the call, for `NO_RECEIPT`).
    pub index: usize,
    /// Window index of the tool call.
    pub call_index: usize,
    /// Denial number (or the receipt's reason for `BLOCKED`; 0 for `NO_RECEIPT`).
    pub reason: u8,
    /// `BLOCKED` only: whether the refusal is justified on re-check.
    pub justified: bool,
}

/// Result of [`audit`].
#[derive(Clone, Debug)]
pub struct AuditReport {
    /// Integrity verification result.
    pub trace: TraceReport,
    /// Authorization findings.
    pub findings: Vec<Finding>,
}

impl AuditReport {
    /// True iff no executed call was unauthorized.
    #[must_use]
    pub fn all_executed_authorized(&self) -> bool {
        !self
            .findings
            .iter()
            .any(|f| f.code == "EXECUTED_UNAUTHORIZED")
    }
}

/// §14.10 offline audit of `transcript.entries[from..]`.
///
/// # Errors
/// v1 integrity errors, `RECEIPT_ORPHAN`, `DUPLICATE_RECEIPT`, `RECEIPT_WRONG_EXECUTOR`.
pub fn audit(
    root: &PublicKey,
    transcript: &Transcript,
    from: usize,
    opts: &VerifyOptions,
) -> Result<AuditReport> {
    let trace = transcript.verify(root, from, opts)?;
    let window = transcript
        .entries
        .get(from..)
        .ok_or(Error::Decode("from beyond end"))?;
    let ids: HashMap<AgentId, &IdentityDocument> = transcript
        .identities
        .iter()
        .map(|d| (d.agent_id(), d))
        .collect();
    let grants: HashMap<Hash32, &Grant> = transcript.grants.iter().map(|g| (g.id(), g)).collect();
    let mut revocations: Vec<(AgentId, Hash32)> = Vec::new();
    let mut calls: HashMap<Hash32, usize> = HashMap::new();
    let mut receipted: Vec<bool> = vec![false; window.len()];
    let mut counters = Counters::new();
    let mut findings = Vec::new();

    for (i, e) in window.iter().enumerate() {
        if e.body().kind == ManifestKind::ToolCall {
            calls.insert(e.entry_hash(), i);
            continue;
        }
        if let Some(target) = e.revocation() {
            revocations.push((e.body().sender, target));
            continue;
        }
        let Some(r) = e.receipt() else { continue };
        let ci = *calls
            .get(&r.call_ref)
            .ok_or(Error::ReceiptOrphan { index: i })?;
        if receipted[ci] {
            return Err(Error::DuplicateReceipt { index: i });
        }
        receipted[ci] = true;
        let call = &window[ci];
        let signer = ids
            .get(&e.body().sender)
            .ok_or(Error::ReceiptWrongExecutor { index: i })?;
        let ok_exec = match &call.body().recipient {
            Recipient::Agent(id) => id.ct_eq(&e.body().sender),
            Recipient::Role(role) => signer.claims().role == *role,
        };
        if !ok_exec {
            return Err(Error::ReceiptWrongExecutor { index: i });
        }
        let ctx = AuthzContext {
            root,
            identities: &ids,
            grants: &grants,
            revocations: &revocations,
        };
        let res = check_authorization(
            &ctx,
            call,
            e.body().timestamp_ms,
            &signer.claims().role,
            &counters,
        );
        match r.status {
            ReceiptStatus::ExecutedOk | ReceiptStatus::ExecutedError => match res {
                Ok(bump) => apply(&mut counters, bump),
                Err(d) => findings.push(Finding {
                    code: "EXECUTED_UNAUTHORIZED",
                    index: i,
                    call_index: ci,
                    reason: d as u8,
                    justified: false,
                }),
            },
            ReceiptStatus::Refused => findings.push(Finding {
                code: "BLOCKED",
                index: i,
                call_index: ci,
                reason: r.reason,
                justified: res.is_err(),
            }),
        }
    }
    let mut unreceipted: Vec<usize> = calls
        .values()
        .copied()
        .filter(|&ci| !receipted[ci])
        .collect();
    unreceipted.sort_unstable();
    for ci in unreceipted {
        findings.push(Finding {
            code: "NO_RECEIPT",
            index: ci,
            call_index: ci,
            reason: 0,
            justified: false,
        });
    }
    Ok(AuditReport { trace, findings })
}
