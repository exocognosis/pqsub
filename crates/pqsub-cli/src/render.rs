//! Human-readable rendering of transcripts and verification reports.

use std::collections::HashMap;
use std::fmt::Write;

use pqsub_core::{AgentId, ManifestKind, Recipient, TraceReport, Transcript};

fn short(id: &AgentId) -> String {
    id.to_hex()[..16].to_string()
}

/// Render a transcript (and optional report) as plain text.
#[must_use]
pub fn transcript_text(t: &Transcript, from: usize, report: Option<&TraceReport>) -> String {
    let names: HashMap<AgentId, &str> = t
        .identities
        .iter()
        .map(|d| (d.agent_id(), d.claims().name.as_str()))
        .collect();
    let name = |id: &AgentId| {
        names
            .get(id)
            .map_or_else(|| short(id), |n| (*n).to_string())
    };
    let mut s = String::new();
    let _ = writeln!(s, "== identities ({}) ==", t.identities.len());
    for d in &t.identities {
        let c = d.claims();
        let _ = writeln!(
            s,
            "  {:<13} role={:<13} id={}… valid=[{}, {}] issuer={}…",
            c.name,
            c.role,
            short(&d.agent_id()),
            c.not_before_ms,
            c.not_after_ms,
            short(&d.issuer_id())
        );
    }
    let _ = writeln!(
        s,
        "== entries ({} total, showing from #{from}) ==",
        t.entries.len()
    );
    for (i, e) in t.entries.iter().enumerate().skip(from) {
        let b = e.body();
        let to = match &b.recipient {
            Recipient::Agent(id) => name(id),
            Recipient::Role(r) => format!("role:{r}"),
        };
        let kind = match b.kind {
            ManifestKind::Handoff => "HANDOFF ",
            ManifestKind::ToolAuthorization => "TOOL-AUTH",
            ManifestKind::ActionRecord => "ACTION  ",
            ManifestKind::ToolCall => "TOOL-CALL",
            ManifestKind::Receipt => "RECEIPT ",
        };
        let _ = writeln!(
            s,
            "#{i} {kind} {} -> {to}  seq={} ts={}",
            name(&b.sender),
            b.seq,
            b.timestamp_ms
        );
        let _ = writeln!(s, "    intent : {}", b.intent);
        if let Some(p) = &b.payload_hash {
            let _ = writeln!(s, "    payload: {p}");
        }
        let _ = writeln!(s, "    prev   : {}", b.prev);
        let _ = writeln!(s, "    hash   : {}", e.entry_hash());
        let _ = writeln!(
            s,
            "    sig    : {}… ({} bytes ML-DSA-65)",
            hex::encode(&e.signature()[..12]),
            e.signature().len()
        );
    }
    if let Some(r) = report {
        let _ = writeln!(s, "== verification ==");
        let _ = writeln!(
            s,
            "  OK: {} entries verified, anchored={}, head={}",
            r.entries.len(),
            r.anchored,
            r.head
        );
    }
    s
}
