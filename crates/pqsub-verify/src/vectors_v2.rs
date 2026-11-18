//! Runner for `test-vectors/vectors-v2.json` (V2_DESIGN §14.11).

use serde::Deserialize;

use crate::vectors::Summary;
use crate::{audit_transcript, caveat_eval, cjson_valid, parse_anchor, parse_h32};

#[derive(Deserialize)]
struct File {
    format: String,
    root_pk: String,
    #[serde(default)]
    cjson: Vec<CjsonCase>,
    #[serde(default)]
    caveats: Vec<CaveatCase>,
    #[serde(default)]
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct CjsonCase {
    name: String,
    input: String,
    object: bool,
    valid: bool,
}

#[derive(Deserialize)]
struct CaveatCase {
    name: String,
    caveat: String,
    decode_ok: bool,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    args: Option<String>,
    #[serde(default)]
    holds: Option<bool>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    #[serde(default)]
    root_pk: Option<String>,
    transcript: String,
    from: usize,
    anchor: String,
    #[serde(default)]
    expected_head: Option<String>,
    expect: Expect,
}

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    head: Option<String>,
    #[serde(default)]
    entry_hashes: Vec<String>,
    #[serde(default)]
    agent_ids: Vec<String>,
    #[serde(default)]
    findings: Vec<FindingV>,
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
struct FindingV {
    code: String,
    index: usize,
    call_index: usize,
    reason: u8,
    #[serde(default)]
    justified: bool,
}

fn h(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| e.to_string())
}

/// Run all v2 vectors in `json`.
///
/// # Errors
/// Only if the file itself is malformed.
pub fn run(json: &str) -> Result<Summary, String> {
    let f: File = serde_json::from_str(json).map_err(|e| e.to_string())?;
    if f.format != "pqsub-test-vectors/v2" {
        return Err(format!("unsupported vector format {}", f.format));
    }
    let mut s = Summary::default();
    let mut check = |ok: bool, what: String| {
        if ok {
            s.passed += 1;
        } else {
            s.failures.push(what);
        }
    };

    for c in &f.cjson {
        let got = cjson_valid(&h(&c.input)?, c.object);
        check(
            got == c.valid,
            format!("cjson {}: got valid={got}, want {}", c.name, c.valid),
        );
    }

    for c in &f.caveats {
        let args = h(c.args.as_deref().unwrap_or(""))?;
        let got = caveat_eval(&h(&c.caveat)?, c.tool.as_deref().unwrap_or(""), &args);
        let want = if c.decode_ok { c.holds } else { None };
        let ok = got.is_some() == c.decode_ok && got == want;
        check(
            ok,
            format!(
                "caveat {}: got {got:?}, want decode_ok={} holds={:?}",
                c.name, c.decode_ok, c.holds
            ),
        );
    }

    for c in &f.cases {
        let root = h(c.root_pk.as_deref().unwrap_or(&f.root_pk))?;
        let tr = h(&c.transcript)?;
        let anchor = parse_anchor(&c.anchor).map_err(|e| e.detail)?;
        let eh = c
            .expected_head
            .as_deref()
            .map(parse_h32)
            .transpose()
            .map_err(|e| e.detail)?;
        match (audit_transcript(&root, &tr, c.from, anchor, eh), &c.expect) {
            (Ok(a), e) if e.ok => {
                let r = &a.report;
                let hashes: Vec<String> = r.entry_hashes.iter().map(hex::encode).collect();
                let ids: Vec<String> = r.senders.iter().map(hex::encode).collect();
                let findings: Vec<FindingV> = a
                    .findings
                    .iter()
                    .map(|f| FindingV {
                        code: f.code.to_string(),
                        index: f.index,
                        call_index: f.call_index,
                        reason: f.reason,
                        justified: f.justified,
                    })
                    .collect();
                let same_values = e.head.as_deref() == Some(hex::encode(r.head).as_str())
                    && hashes == e.entry_hashes
                    && ids == e.agent_ids;
                check(same_values, format!("case {}: values differ", c.name));
                check(
                    findings == e.findings,
                    format!(
                        "case {}: findings differ (got {findings:?}, want {:?})",
                        c.name, e.findings
                    ),
                );
            }
            (Err(fl), e) if !e.ok => check(
                e.error.as_deref() == Some(fl.code),
                format!("case {}: code {} != {:?}", c.name, fl.code, e.error),
            ),
            (got, _) => check(
                false,
                format!(
                    "case {}: verdict mismatch (got {:?})",
                    c.name,
                    got.map(|_| "ok")
                ),
            ),
        }
    }
    Ok(s)
}
