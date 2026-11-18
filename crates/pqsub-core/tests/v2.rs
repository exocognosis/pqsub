//! v2 tests: canonical JSON, caveats, grants, gate, audit.

use pqsub_core::caveat::{abs_path_segments, email_domain, url_origin, valid_host};
use pqsub_core::cjson::{self, parse_canonical};
use pqsub_core::*;

const DET: SigningMode = SigningMode::Deterministic;
const T0: u64 = 1_767_225_600_000;
const MIN: u64 = 60_000;

fn kp(tag: u8) -> AgentKeypair {
    AgentKeypair::from_seed(&[tag; 32]).unwrap()
}
fn ident(root: &AgentKeypair, a: &AgentKeypair, name: &str, role: &str) -> IdentityDocument {
    let c = IdentityClaims {
        name: name.into(),
        role: role.into(),
        not_before_ms: T0,
        not_after_ms: T0 + 365 * 1440 * MIN,
    };
    IdentityDocument::issue(root, a.public_key(), c, DET).unwrap()
}
fn cav(scope: Option<&str>, kind: CaveatKind) -> Caveat {
    Caveat {
        scope: scope.map_or(Scope::All, |t| Scope::Tool(t.into())),
        kind,
    }
}
fn s(v: &str) -> Vec<u8> {
    v.as_bytes().to_vec()
}

// ------------------------------------------------------------------ cjson

#[test]
fn cjson_acceptance() {
    let ok = |x: &str| parse_canonical(x.as_bytes(), true).is_ok();
    assert!(ok(r#"{}"#));
    assert!(ok(r#"{"a":1,"b":[true,false,null],"c":"x"}"#));
    assert!(ok(r#"{"n":-9007199254740991,"p":9007199254740991}"#));
    assert!(ok("{\"s\":\"\\\"\\\\\\b\\f\\n\\r\\t\\u001f/\u{7f}é\"}"));
    // UTF-16 ordering: U+FF61 (BMP, 0xFF61) sorts AFTER U+1F600 (surrogates 0xD83D…).
    assert!(ok("{\"\u{1F600}\":1,\"\u{FF61}\":2}"));
    assert!(!ok("{\"\u{FF61}\":2,\"\u{1F600}\":1}"));
    for bad in [
        r#"{"b":1,"a":2}"#,          // order
        r#"{"a":1,"a":1}"#,          // duplicate
        r#"{ "a":1}"#,               // whitespace
        r#"{"a":1.0}"#,              // float
        r#"{"a":1e3}"#,              // exponent
        r#"{"a":-0}"#,               // negative zero
        r#"{"a":01}"#,               // leading zero
        r#"{"a":9007199254740992}"#, // > 2^53-1
        r#"{"a":"\u0041"}"#,         // non-canonical escape
        r#"{"a":"\/"}"#,             // non-canonical escape
        r#"{"a":"\ud800"}"#,         // lone surrogate
        r#"{"a":[[[[1]]]]}"#,        // depth 5
        r#"[1]"#,                    // not an object
        r#"{"a":1}x"#,               // trailing
        "{\"a\":\"\u{1}\"}",         // raw control char
    ] {
        assert!(!ok(bad), "accepted {bad}");
    }
    assert!(parse_canonical(b"[[[1]]]", false).is_ok());
    assert!(parse_canonical(b"\"x\"", false).is_ok());
    assert!(parse_canonical(&vec![b'1'; 2000], false).is_err()); // > 1024 for values
}

#[test]
fn json_pointer() {
    let v = parse_canonical(br#"{"a/b":{"~k":[10,20]},"x":1}"#, true).unwrap();
    assert_eq!(
        cjson::pointer(&v, "/a~1b/~0k/1"),
        Some(&cjson::Value::Int(20))
    );
    assert_eq!(cjson::pointer(&v, "/a~1b/~0k/01"), None);
    assert_eq!(cjson::pointer(&v, "/a~1b/~0k/-"), None);
    assert_eq!(cjson::pointer(&v, "/x/y"), None);
    assert_eq!(cjson::pointer(&v, ""), Some(&v));
    assert!(cjson::validate_pointer("/a~2").is_err());
    assert!(cjson::validate_pointer("a").is_err());
}

// ------------------------------------------------------------------ matchers

#[test]
fn matcher_bypass_attempts_fail() {
    let under = |v: &str| {
        let c = cav(
            None,
            CaveatKind::PathUnder {
                path: "/p".into(),
                root: "/workspace".into(),
            },
        );
        let args = parse_canonical(
            format!(
                "{{\"p\":{}}}",
                String::from_utf8(cjson::encode(&cjson::Value::Str(v.into()))).unwrap()
            )
            .as_bytes(),
            true,
        )
        .unwrap();
        c.holds("t", &args, &Recipient::Role("r".into()), "r")
    };
    assert!(under("/workspace/a/b.txt"));
    assert!(under("/workspace"));
    for bad in [
        "/workspace/../etc/passwd",
        "/workspace-evil/x",
        "/workspace/",
        "/workspace//x",
        "/workspace/./x",
        "workspace/x",
        "/workspace\\x",
        "/etc",
    ] {
        assert!(!under(bad), "{bad}");
    }
    assert_eq!(
        url_origin("https://acme.com/x?y#z").as_deref(),
        Some("https://acme.com:443")
    );
    assert_eq!(
        url_origin("http://acme.com:8080").as_deref(),
        Some("http://acme.com:8080")
    );
    for bad in [
        "https://acme.com.evil.com",
        "https://evil@acme.com",
        "https://ACME.com",
        "https://1.2.3.4",
        "ftp://acme.com",
        "https://acme.com:0",
        "https://acme.com:080",
        "https://",
    ] {
        assert_ne!(
            url_origin(bad).as_deref(),
            Some("https://acme.com:443"),
            "{bad}"
        );
    }
    assert!(url_origin("https://acme.com.evil.com").is_some()); // valid URL, different origin
    assert_eq!(email_domain("Bob@ACME.com").as_deref(), Some("acme.com"));
    for bad in [
        "x@acme.com@evil",
        "@acme.com",
        "bob acme@acme.com",
        "bob@",
        "bob@acme..com",
        "bób@acme.com",
    ] {
        assert!(email_domain(bad).is_none(), "{bad}");
    }
    assert!(valid_host("a-b.example"));
    assert!(!valid_host("-a.example") && !valid_host("10.0.0.1") && !valid_host("A.com"));
    assert_eq!(abs_path_segments("/").unwrap().len(), 0);
}

#[test]
fn caveat_codec_and_constraints() {
    let all = vec![
        cav(None, CaveatKind::ToolAllow(vec!["send_money".into()])),
        cav(
            Some("send_money"),
            CaveatKind::ArgEq {
                path: "/to".into(),
                value: s("\"DE89\""),
            },
        ),
        cav(
            None,
            CaveatKind::ArgOneOf {
                path: "/n".into(),
                values: vec![s("1"), s("[1,2]")],
            },
        ),
        cav(
            None,
            CaveatKind::IntRange {
                path: "/amount".into(),
                min: -5,
                max: 120_000,
            },
        ),
        cav(
            None,
            CaveatKind::PathUnder {
                path: "/p".into(),
                root: "/".into(),
            },
        ),
        cav(
            None,
            CaveatKind::UrlOrigin {
                path: "/u".into(),
                origins: vec!["https://acme.com:443".into()],
            },
        ),
        cav(
            None,
            CaveatKind::EmailDomain {
                path: "/to".into(),
                domains: vec!["acme.com".into()],
            },
        ),
        cav(None, CaveatKind::MaxCalls(3)),
        cav(None, CaveatKind::Executor(vec!["bank".into()])),
    ];
    for c in &all {
        let e = c.encode().unwrap();
        assert_eq!(&Caveat::decode(&e).unwrap(), c);
    }
    let bad = [
        cav(Some("x"), CaveatKind::ToolAllow(vec!["a".into()])),
        cav(None, CaveatKind::ToolAllow(vec!["Bad Name".into()])),
        cav(
            None,
            CaveatKind::ArgEq {
                path: "/a".into(),
                value: s("{ }"),
            },
        ),
        cav(
            None,
            CaveatKind::IntRange {
                path: "/a".into(),
                min: 2,
                max: 1,
            },
        ),
        cav(
            None,
            CaveatKind::PathUnder {
                path: "/a".into(),
                root: "/x/".into(),
            },
        ),
        cav(
            None,
            CaveatKind::UrlOrigin {
                path: "/a".into(),
                origins: vec!["https://acme.com".into()],
            },
        ),
        cav(
            None,
            CaveatKind::EmailDomain {
                path: "/a".into(),
                domains: vec!["ACME.com".into()],
            },
        ),
        cav(None, CaveatKind::MaxCalls(0)),
        cav(None, CaveatKind::Executor(vec![])),
    ];
    for c in &bad {
        assert_eq!(c.encode().unwrap_err().code(), "INVALID_FIELD", "{c:?}");
    }
    // MaxCalls without Executor in the same grant is rejected.
    let spec = GrantSpec {
        audience: kp(2).agent_id(),
        parent: Hash32::ZERO,
        not_before_ms: 0,
        not_after_ms: 1,
        depth: 1,
        nonce: [0; 16],
        caveats: vec![cav(None, CaveatKind::MaxCalls(1))],
    };
    assert_eq!(
        Grant::issue(&kp(1), spec, DET).unwrap_err().code(),
        "INVALID_FIELD"
    );
}

// ------------------------------------------------------------------ scenario

struct World {
    root: AgentKeypair,
    principal: AgentKeypair,
    orch: AgentKeypair,
    agent: AgentKeypair,
    ids: Vec<IdentityDocument>,
    g: Vec<Grant>,
    bank: Gate,
    mail_key: AgentKeypair,
}

fn grant(
    issuer: &AgentKeypair,
    aud: &AgentKeypair,
    parent: Hash32,
    depth: u8,
    until: u64,
    caveats: Vec<Caveat>,
) -> Grant {
    let spec = GrantSpec {
        audience: aud.agent_id(),
        parent,
        not_before_ms: T0,
        not_after_ms: until,
        depth,
        nonce: [depth; 16],
        caveats,
    };
    Grant::issue(issuer, spec, DET).unwrap()
}

fn world() -> World {
    let (root, principal, orch, agent, bank_k, mail_k) = (kp(1), kp(2), kp(3), kp(4), kp(5), kp(6));
    let ids = vec![
        ident(&root, &principal, "principal", "principal"),
        ident(&root, &orch, "orchestrator", "orchestrator"),
        ident(&root, &agent, "agent", "worker"),
        ident(&root, &bank_k, "bank", "bank"),
        ident(&root, &mail_k, "mail", "mail"),
    ];
    let g0 = grant(
        &root,
        &principal,
        Hash32::ZERO,
        3,
        T0 + 365 * 1440 * MIN,
        vec![cav(
            None,
            CaveatKind::ToolAllow(vec![
                "get_balance".into(),
                "send_money".into(),
                "send_email".into(),
            ]),
        )],
    );
    let g1 = grant(
        &principal,
        &orch,
        g0.id(),
        2,
        T0 + 30 * MIN,
        vec![
            cav(
                Some("send_money"),
                CaveatKind::ArgOneOf {
                    path: "/to".into(),
                    values: vec![s("\"DE89LANDLORD\"")],
                },
            ),
            cav(
                Some("send_money"),
                CaveatKind::IntRange {
                    path: "/amount".into(),
                    min: 1,
                    max: 120_000,
                },
            ),
            cav(
                Some("send_money"),
                CaveatKind::Executor(vec!["bank".into()]),
            ),
            cav(Some("send_money"), CaveatKind::MaxCalls(2)),
            cav(
                Some("send_email"),
                CaveatKind::EmailDomain {
                    path: "/to".into(),
                    domains: vec!["acme.com".into()],
                },
            ),
        ],
    );
    let g2 = grant(
        &orch,
        &agent,
        g1.id(),
        1,
        T0 + 30 * MIN,
        vec![cav(
            None,
            CaveatKind::ToolAllow(vec!["get_balance".into(), "send_money".into()]),
        )],
    );
    let mut bank = Gate::new(root.public_key().clone(), bank_k, ids.clone()).unwrap();
    for g in [&g0, &g1, &g2] {
        bank.add_grant(g.clone());
    }
    World {
        root,
        principal,
        orch,
        agent,
        ids,
        g: vec![g0, g1, g2],
        bank,
        mail_key: mail_k,
    }
}

fn call(
    tb: &mut TraceBuilder,
    who: &AgentKeypair,
    to: &str,
    tool: &str,
    args: &str,
    chain: Vec<Hash32>,
    ts: u64,
) -> SignedManifest {
    let spec = EntrySpec {
        kind: ManifestKind::ToolCall,
        recipient: Recipient::Role(to.into()),
        intent: format!("{tool} {args}"),
        payload_hash: None,
        timestamp_ms: ts,
    };
    let ext = Ext::ToolCall(ToolCall {
        tool: tool.into(),
        args: s(args),
        chain,
    });
    tb.append_ext(who, spec, ext, DET).unwrap().clone()
}

fn receipt(
    tb: &mut TraceBuilder,
    gate_key: &AgentKeypair,
    c: &SignedManifest,
    out: Outcome<'_>,
    ts: u64,
) {
    let spec = EntrySpec {
        kind: ManifestKind::Receipt,
        recipient: Recipient::Agent(c.body().sender),
        intent: "receipt".into(),
        payload_hash: None,
        timestamp_ms: ts,
    };
    tb.append_ext(gate_key, spec, receipt_ext(c, out).unwrap(), DET)
        .unwrap();
}

fn chain(w: &World) -> Vec<Hash32> {
    w.g.iter().map(Grant::id).collect()
}

#[test]
fn gate_enforces_grants() {
    let mut w = world();
    let mut tb = TraceBuilder::new();
    let t = T0 + MIN;
    let pay = r#"{"amount":95000,"to":"DE89LANDLORD"}"#;
    let c = call(&mut tb, &w.agent, "bank", "send_money", pay, chain(&w), t);
    assert_eq!(w.bank.check(&c, t), Ok(()));
    assert_eq!(
        w.bank.check(&c, t),
        Err(Denial::CallInvalid),
        "replay of the same signed call"
    );

    let attack = call(
        &mut tb,
        &w.agent,
        "bank",
        "send_money",
        r#"{"amount":5000,"to":"GB00ATTACKER"}"#,
        chain(&w),
        t,
    );
    assert_eq!(w.bank.check(&attack, t), Err(Denial::CaveatViolation));
    let too_much = call(
        &mut tb,
        &w.agent,
        "bank",
        "send_money",
        r#"{"amount":120001,"to":"DE89LANDLORD"}"#,
        chain(&w),
        t,
    );
    assert_eq!(w.bank.check(&too_much, t), Err(Denial::CaveatViolation));
    let missing = call(
        &mut tb,
        &w.agent,
        "bank",
        "send_money",
        r#"{"to":"DE89LANDLORD"}"#,
        chain(&w),
        t,
    );
    assert_eq!(
        w.bank.check(&missing, t),
        Err(Denial::CaveatViolation),
        "absent path fails closed"
    );
    let email = call(
        &mut tb,
        &w.agent,
        "bank",
        "send_email",
        r#"{"to":"a@acme.com"}"#,
        chain(&w),
        t,
    );
    assert_eq!(
        w.bank.check(&email, t),
        Err(Denial::CaveatViolation),
        "dropped by g2 ToolAllow"
    );
    let to_mail = call(&mut tb, &w.agent, "mail", "get_balance", "{}", chain(&w), t);
    assert_eq!(w.bank.check(&to_mail, t), Err(Denial::WrongExecutor));

    let c2 = call(&mut tb, &w.agent, "bank", "send_money", pay, chain(&w), t);
    assert_eq!(w.bank.check(&c2, t), Ok(()));
    let c3 = call(&mut tb, &w.agent, "bank", "send_money", pay, chain(&w), t);
    assert_eq!(w.bank.check(&c3, t), Err(Denial::BudgetExceeded));
    let bal = call(&mut tb, &w.agent, "bank", "get_balance", "{}", chain(&w), t);
    assert_eq!(
        w.bank.check(&bal, t),
        Ok(()),
        "MaxCalls scoped to send_money"
    );

    let late = call(
        &mut tb,
        &w.agent,
        "bank",
        "get_balance",
        "{}",
        chain(&w),
        T0 + 31 * MIN,
    );
    assert_eq!(
        w.bank.check(&late, T0 + 31 * MIN),
        Err(Denial::GrantExpired)
    );
    let unknown = call(
        &mut tb,
        &w.agent,
        "bank",
        "get_balance",
        "{}",
        vec![w.g[0].id(), Hash32([9; 32])],
        t,
    );
    assert_eq!(w.bank.check(&unknown, t), Err(Denial::GrantUnknown));
}

#[test]
fn delegation_can_only_attenuate() {
    let mut w = world();
    let mut tb = TraceBuilder::new();
    let t = T0 + MIN;
    // The (possibly injected) agent mints itself a caveat-free sub-grant: allowed, but useless.
    let g3 = grant(&w.agent, &w.agent, w.g[2].id(), 0, T0 + 30 * MIN, vec![]);
    w.bank.add_grant(g3.clone());
    let mut ch = chain(&w);
    ch.push(g3.id());
    let attack = call(
        &mut tb,
        &w.agent,
        "bank",
        "send_money",
        r#"{"amount":5000,"to":"GB00ATTACKER"}"#,
        ch,
        t,
    );
    assert_eq!(w.bank.check(&attack, t), Err(Denial::CaveatViolation));
    // Skipping the orchestrator's grant breaks linkage.
    let skip = grant(&w.agent, &w.agent, w.g[0].id(), 0, T0 + 30 * MIN, vec![]);
    w.bank.add_grant(skip.clone());
    let c = call(
        &mut tb,
        &w.agent,
        "bank",
        "get_balance",
        "{}",
        vec![w.g[0].id(), skip.id()],
        t,
    );
    assert_eq!(w.bank.check(&c, t), Err(Denial::GrantChain));
    // Depth must strictly decrease.
    let flat = grant(&w.orch, &w.agent, w.g[1].id(), 2, T0 + 30 * MIN, vec![]);
    w.bank.add_grant(flat.clone());
    let c = call(
        &mut tb,
        &w.agent,
        "bank",
        "get_balance",
        "{}",
        vec![w.g[0].id(), w.g[1].id(), flat.id()],
        t,
    );
    assert_eq!(w.bank.check(&c, t), Err(Denial::GrantChain));
    // A grant used by someone other than its audience.
    let c = call(&mut tb, &w.orch, "bank", "get_balance", "{}", chain(&w), t);
    assert_eq!(w.bank.check(&c, t), Err(Denial::GrantChain));
    // Root grant must come from the root key.
    let fake_root = grant(
        &w.principal,
        &w.agent,
        Hash32::ZERO,
        3,
        T0 + 30 * MIN,
        vec![],
    );
    w.bank.add_grant(fake_root.clone());
    let c = call(
        &mut tb,
        &w.agent,
        "bank",
        "get_balance",
        "{}",
        vec![fake_root.id()],
        t,
    );
    assert_eq!(w.bank.check(&c, t), Err(Denial::GrantChain));
    // Tampered grant: decodes, but its signature no longer verifies.
    let mut enc = w.g[2].encode();
    let nonce_pos = 4 + 1 + 32 * 3 + 16 + 1;
    enc[nonce_pos] ^= 1;
    let tampered = Grant::decode(&enc).unwrap();
    w.bank.add_grant(tampered.clone());
    let c = call(
        &mut tb,
        &w.agent,
        "bank",
        "get_balance",
        "{}",
        vec![w.g[0].id(), w.g[1].id(), tampered.id()],
        t,
    );
    assert_eq!(w.bank.check(&c, t), Err(Denial::GrantInvalid));
}

fn audited(w: &World, tb: TraceBuilder) -> Result<AuditReport> {
    let t = Transcript {
        identities: w.ids.clone(),
        grants: w.g.clone(),
        entries: tb.into_entries(),
    };
    let t = Transcript::decode(&t.encode().unwrap()).unwrap();
    audit(w.root.public_key(), &t, 0, &VerifyOptions::default())
}

#[test]
fn audit_reports_blocked_and_unauthorized_execution() {
    let mut w = world();
    let mut tb = TraceBuilder::new();
    let t = T0 + MIN;
    let bank_key = AgentKeypair::from_seed(&[5; 32]).unwrap();
    let ok = call(
        &mut tb,
        &w.agent,
        "bank",
        "send_money",
        r#"{"amount":95000,"to":"DE89LANDLORD"}"#,
        chain(&w),
        t,
    );
    w.bank.check(&ok, t).unwrap();
    receipt(&mut tb, &bank_key, &ok, Outcome::Ok(b"tx-1"), t + 1);
    let attack = call(
        &mut tb,
        &w.agent,
        "bank",
        "send_money",
        r#"{"amount":5000,"to":"GB00ATTACKER"}"#,
        chain(&w),
        t + 2,
    );
    let d = w.bank.check(&attack, t + 2).unwrap_err();
    receipt(&mut tb, &bank_key, &attack, Outcome::Refused(d), t + 3);
    let pending = call(
        &mut tb,
        &w.agent,
        "bank",
        "get_balance",
        "{}",
        chain(&w),
        t + 4,
    );
    let _ = pending;
    let r = audited(&w, tb).unwrap();
    assert!(r.all_executed_authorized());
    let codes: Vec<_> = r
        .findings
        .iter()
        .map(|f| (f.code, f.index, f.call_index, f.reason, f.justified))
        .collect();
    assert_eq!(
        codes,
        vec![("BLOCKED", 3, 2, 6, true), ("NO_RECEIPT", 4, 4, 0, false)]
    );

    // A buggy/compromised executor runs the attack anyway: the audit catches it.
    let mut tb = TraceBuilder::new();
    let attack = call(
        &mut tb,
        &w.agent,
        "bank",
        "send_money",
        r#"{"amount":5000,"to":"GB00ATTACKER"}"#,
        chain(&w),
        t,
    );
    receipt(&mut tb, &bank_key, &attack, Outcome::Ok(b"tx-evil"), t + 1);
    let r = audited(&w, tb).unwrap();
    assert!(!r.all_executed_authorized());
    assert_eq!(r.findings[0].code, "EXECUTED_UNAUTHORIZED");
    assert_eq!(r.findings[0].reason, Denial::CaveatViolation as u8);

    // Receipt time (executor clock) decides expiry, not the caller's timestamp.
    let mut tb = TraceBuilder::new();
    let backdated = call(&mut tb, &w.agent, "bank", "get_balance", "{}", chain(&w), t);
    receipt(
        &mut tb,
        &bank_key,
        &backdated,
        Outcome::Ok(b"1"),
        T0 + 45 * MIN,
    );
    let r = audited(&w, tb).unwrap();
    assert_eq!(
        (r.findings[0].code, r.findings[0].reason),
        ("EXECUTED_UNAUTHORIZED", Denial::GrantExpired as u8)
    );
}

#[test]
fn audit_fatal_receipt_errors() {
    let w = world();
    let t = T0 + MIN;
    let bank_key = AgentKeypair::from_seed(&[5; 32]).unwrap();
    // Wrong executor: mail signs a receipt for a bank call.
    let mut tb = TraceBuilder::new();
    let c = call(&mut tb, &w.agent, "bank", "get_balance", "{}", chain(&w), t);
    receipt(&mut tb, &w.mail_key, &c, Outcome::Ok(b"1"), t);
    assert_eq!(
        audited(&w, tb).unwrap_err().code(),
        "RECEIPT_WRONG_EXECUTOR"
    );
    // Duplicate receipt.
    let mut tb = TraceBuilder::new();
    let c = call(&mut tb, &w.agent, "bank", "get_balance", "{}", chain(&w), t);
    receipt(&mut tb, &bank_key, &c, Outcome::Ok(b"1"), t);
    receipt(&mut tb, &bank_key, &c, Outcome::Ok(b"1"), t);
    assert_eq!(audited(&w, tb).unwrap_err().code(), "DUPLICATE_RECEIPT");
    // Orphan: receipt for a call outside the audited window.
    let mut tb = TraceBuilder::new();
    let c = call(&mut tb, &w.agent, "bank", "get_balance", "{}", chain(&w), t);
    receipt(&mut tb, &bank_key, &c, Outcome::Ok(b"1"), t);
    let t2 = Transcript {
        identities: w.ids.clone(),
        grants: w.g.clone(),
        entries: tb.into_entries(),
    };
    let opts = VerifyOptions {
        anchor: Anchor::Unanchored,
        expected_head: None,
    };
    assert_eq!(
        audit(w.root.public_key(), &t2, 1, &opts)
            .unwrap_err()
            .code(),
        "RECEIPT_ORPHAN"
    );
}

#[test]
fn transcript_v2_canonical_rules_and_tamper() {
    let mut w = world();
    let t = T0 + MIN;
    let bank_key = AgentKeypair::from_seed(&[5; 32]).unwrap();
    let mut tb = TraceBuilder::new();
    tb.append(
        &w.orch,
        EntrySpec {
            kind: ManifestKind::Handoff,
            recipient: Recipient::Agent(w.agent.agent_id()),
            intent: "pay rent".into(),
            payload_hash: None,
            timestamp_ms: t,
        },
        DET,
    )
    .unwrap();
    let c = call(
        &mut tb,
        &w.agent,
        "bank",
        "send_money",
        r#"{"amount":95000,"to":"DE89LANDLORD"}"#,
        chain(&w),
        t,
    );
    w.bank.check(&c, t).unwrap();
    receipt(&mut tb, &bank_key, &c, Outcome::Ok(b"tx"), t);
    let tr = Transcript {
        identities: w.ids.clone(),
        grants: w.g.clone(),
        entries: tb.into_entries(),
    };
    let enc = tr.encode().unwrap();
    assert_eq!(enc[4], 2);
    assert_eq!(Transcript::decode(&enc).unwrap().encode().unwrap(), enc);
    // Duplicate grant -> DECODE.
    let mut dup = tr.clone();
    dup.grants.push(w.g[0].clone());
    assert_eq!(
        Transcript::decode(&dup.encode().unwrap())
            .unwrap_err()
            .code(),
        "DECODE"
    );
    // v2 container with no grants and only v1 entries is non-canonical.
    let v1only = Transcript {
        identities: w.ids.clone(),
        grants: vec![],
        entries: vec![tr.entries[0].clone()],
    };
    let mut x = v1only.encode().unwrap();
    assert_eq!(x[4], 1);
    x[4] = 2;
    x.splice(
        5 + 2 + w.ids.iter().map(|d| 4 + d.encode().len()).sum::<usize>()..,
        [0u8, 0u8]
            .iter()
            .copied()
            .chain(x[5 + 2 + w.ids.iter().map(|d| 4 + d.encode().len()).sum::<usize>()..].to_vec()),
    );
    assert_eq!(Transcript::decode(&x).unwrap_err().code(), "DECODE");
    // Sampled bit flips across the whole v2 transcript never pass audit unchanged.
    let root = w.root.public_key();
    for bit in (0..enc.len() * 8).step_by(211) {
        let mut y = enc.clone();
        y[bit / 8] ^= 1 << (bit % 8);
        let res =
            Transcript::decode(&y).and_then(|t| audit(root, &t, 0, &VerifyOptions::default()));
        // Detected = fatal error, or the (originally empty) findings changed,
        // e.g. a flipped grant makes the executed call EXECUTED_UNAUTHORIZED.
        if let Ok(r) = res {
            assert!(
                !r.findings.is_empty(),
                "bit {bit} flip passed audit unchanged"
            );
        }
    }
}
