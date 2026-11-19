//! Wrap a real tool (writing files) in a pqsub gate.
//!
//! ```text
//! cargo run --release --example gated_tool
//! ```
//!
//! An agent holds a grant that allows `write_file` only under a sandbox
//! directory. It asks for two writes: one inside the sandbox and one that
//! escapes it with `../` (what a prompt-injected agent might try). The gate
//! runs the first, refuses the second, and signs a receipt for each. An
//! independent verifier (`pqsub-verify`, separate code and ML-DSA library)
//! then audits the transcript using only the root public key.
//!
//! The wrapping itself is the `gate.execute(...)` call in `main`; everything
//! else is key, identity and grant setup that a deployment does once.
//! Note: `PathUnder` checks the path string; a real file tool should also
//! refuse to follow symlinks out of the sandbox.

use pqsub_core::*;

const T0: u64 = 1_800_000_000_000;
const HOUR: u64 = 3_600_000;

/// The real tool: write `content` to `path`. Knows nothing about pqsub.
fn write_file(args: &[u8]) -> std::result::Result<Vec<u8>, Vec<u8>> {
    let a: serde_json::Value =
        serde_json::from_slice(args).map_err(|e| e.to_string().into_bytes())?;
    let (path, content) = (
        a["path"].as_str().unwrap_or(""),
        a["content"].as_str().unwrap_or(""),
    );
    std::fs::write(path, content).map_err(|e| e.to_string().into_bytes())?;
    Ok(format!("wrote {} bytes", content.len()).into_bytes())
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let sandbox = std::env::temp_dir().join(format!("pqsub-gated-tool-{}", std::process::id()));
    std::fs::create_dir_all(&sandbox)?;
    let sandbox_str = sandbox.to_str().ok_or("non-UTF-8 temp dir")?.to_string();

    // --- one-time setup: keys, identities, grants -------------------------------
    let (root, principal, agent, fs) = (
        AgentKeypair::generate()?,
        AgentKeypair::generate()?,
        AgentKeypair::generate()?,
        AgentKeypair::generate()?,
    );
    let id = |k: &AgentKeypair, role: &str| {
        let claims = IdentityClaims {
            name: role.into(),
            role: role.into(),
            not_before_ms: T0,
            not_after_ms: T0 + HOUR,
        };
        IdentityDocument::issue(&root, k.public_key(), claims, SigningMode::Hedged)
    };
    let identities = vec![
        id(&principal, "principal")?,
        id(&agent, "worker")?,
        id(&fs, "fs")?,
    ];
    let caveat = |kind| Caveat {
        scope: Scope::All,
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
    // Root -> principal: may use write_file. Principal -> agent: only under the sandbox, only via the fs executor.
    let g0 = Grant::issue(
        &root,
        spec(
            &principal,
            Hash32::ZERO,
            1,
            vec![caveat(CaveatKind::ToolAllow(vec!["write_file".into()]))],
        ),
        SigningMode::Hedged,
    )?;
    let g1 = Grant::issue(
        &principal,
        spec(
            &agent,
            g0.id(),
            0,
            vec![
                caveat(CaveatKind::PathUnder {
                    path: "/path".into(),
                    root: sandbox_str.clone(),
                }),
                caveat(CaveatKind::Executor(vec!["fs".into()])),
            ],
        ),
        SigningMode::Hedged,
    )?;

    // --- the executor's gate ------------------------------------------------------
    let mut gate = Gate::new(root.public_key().clone(), fs, identities.clone())?;
    gate.add_grant(g0.clone());
    gate.add_grant(g1.clone());

    let mut trace = TraceBuilder::new();
    let attempts = [
        format!("{sandbox_str}/report.txt"),   // allowed
        format!("{sandbox_str}/../pwned.txt"), // escapes the sandbox
    ];
    for (i, path) in attempts.iter().enumerate() {
        let now = T0 + 1000 * (i as u64 + 1);
        // Agent side: a signed tool call carrying canonical JSON args and its grant chain.
        let args = cjson::encode(&cjson::Value::Obj(vec![
            ("content".into(), cjson::Value::Str("hello".into())),
            ("path".into(), cjson::Value::Str(path.clone())),
        ]));
        let call_spec = EntrySpec {
            kind: ManifestKind::ToolCall,
            recipient: Recipient::Role("fs".into()),
            intent: "write_file".into(),
            payload_hash: None,
            timestamp_ms: now,
        };
        let ext = Ext::ToolCall(ToolCall {
            tool: "write_file".into(),
            args,
            chain: vec![g0.id(), g1.id()],
        });
        let call = trace
            .append_ext(&agent, call_spec, ext, SigningMode::Hedged)?
            .clone();

        // Executor side: this is the whole integration.
        let receipt = gate
            .execute(&call, now, write_file)
            .map_err(|d| format!("{d:?}"))?;

        let Ext::Receipt(r) = &receipt else {
            unreachable!()
        };
        println!(
            "{:<26} -> {:?} (reason {})",
            path.replace(&sandbox_str, "$SANDBOX"),
            r.status,
            r.reason
        );
        let rspec = EntrySpec {
            kind: ManifestKind::Receipt,
            recipient: Recipient::Agent(agent.agent_id()),
            intent: "receipt".into(),
            payload_hash: None,
            timestamp_ms: now,
        };
        trace.append_ext(gate.key(), rspec, receipt, SigningMode::Hedged)?;
    }
    let escaped = sandbox
        .parent()
        .map(|p| p.join("pwned.txt"))
        .ok_or("no parent")?;
    println!("file outside sandbox exists: {}", escaped.exists());

    // --- third-party audit with the independent verifier --------------------------
    let t = Transcript {
        identities,
        grants: vec![g0, g1],
        entries: trace.into_entries(),
    }
    .encode()?;
    let root_pk = pqsub_verify::parse_root(&root.public_key().to_file_bytes())
        .map_err(|f| format!("{f:?}"))?;
    let report =
        pqsub_verify::audit_transcript(&root_pk, &t, 0, pqsub_verify::Anchor::Genesis, None)
            .map_err(|f| format!("{f:?}"))?;
    for f in &report.findings {
        println!(
            "audit: {} entry #{} reason={} justified={}",
            f.code, f.index, f.reason, f.justified
        );
    }
    let unauthorized = report
        .findings
        .iter()
        .any(|f| f.code == "EXECUTED_UNAUTHORIZED");
    println!("audit: every executed call authorized = {}", !unauthorized);
    std::fs::remove_dir_all(&sandbox)?;
    if unauthorized || escaped.exists() {
        return Err("gate failed to contain the tool".into());
    }
    Ok(())
}
