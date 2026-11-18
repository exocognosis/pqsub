//! Deterministic v2 test vectors (`test-vectors/vectors-v2.json`, V2_DESIGN §14.11).
//!
//! Every case states its intended outcome; generation fails if `pqsub-core`
//! disagrees. `pqsub-verify` must agree independently.

use anyhow::{bail, Result};
use pqsub_core::caveat::{Caveat, CaveatKind, Scope};
use pqsub_core::cjson::{self, Value};
use pqsub_core::{
    audit, payload_hash, receipt_ext, AgentKeypair, Denial, EntrySpec, Ext, Grant, GrantSpec,
    Hash32, IdentityClaims, IdentityDocument, ManifestKind, Outcome, PublicKey, Recipient,
    SignedManifest, SigningMode, ToolCall, TraceBuilder, Transcript, VerifyOptions, CTX_GRANT,
    SIGNATURE_LEN,
};
use serde::{Deserialize, Serialize};

use crate::vectors::parse_anchor;

const DET: SigningMode = SigningMode::Deterministic;
const T0: u64 = 1_767_225_600_000;
const MIN: u64 = 60_000;

/// Top-level v2 vector file.
#[derive(Serialize, Deserialize, Debug)]
pub struct VectorsV2 {
    /// `pqsub-test-vectors/v2`.
    pub format: String,
    /// Default trust anchor (hex raw pk).
    pub root_pk: String,
    /// Canonical-JSON acceptance cases.
    pub cjson: Vec<CjsonCase>,
    /// Caveat decode / evaluation cases.
    pub caveats: Vec<CaveatCase>,
    /// Transcript audit cases.
    pub cases: Vec<AuditCase>,
}

/// cjson acceptance.
#[derive(Serialize, Deserialize, Debug)]
pub struct CjsonCase {
    /// Name.
    pub name: String,
    /// Hex input.
    pub input: String,
    /// Top-level object required (tool args) vs caveat value.
    pub object: bool,
    /// Expected acceptance.
    pub valid: bool,
}

/// Caveat decode/evaluation.
#[derive(Serialize, Deserialize, Debug)]
pub struct CaveatCase {
    /// Name.
    pub name: String,
    /// Hex encoded caveat.
    pub caveat: String,
    /// Whether it decodes.
    pub decode_ok: bool,
    /// Tool name of the call.
    pub tool: String,
    /// Hex canonical args object.
    pub args: String,
    /// Whether it holds (`None` if it does not decode).
    pub holds: Option<bool>,
}

/// One transcript audit case.
#[derive(Serialize, Deserialize, Debug)]
pub struct AuditCase {
    /// Name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Optional root override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_pk: Option<String>,
    /// Hex transcript.
    pub transcript: String,
    /// Window start.
    pub from: usize,
    /// Anchor.
    pub anchor: String,
    /// Optional expected head.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_head: Option<String>,
    /// Expected outcome.
    pub expect: AuditExpect,
}

/// Expected audit outcome.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct AuditExpect {
    /// No fatal error.
    pub ok: bool,
    /// Fatal error code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Head (if ok).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    /// Entry hashes (if ok).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entry_hashes: Vec<String>,
    /// Sender ids (if ok).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_ids: Vec<String>,
    /// Findings (if ok).
    #[serde(default)]
    pub findings: Vec<FindingV>,
}

/// Serialized finding.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct FindingV {
    /// Code.
    pub code: String,
    /// Window index.
    pub index: usize,
    /// Call window index.
    pub call_index: usize,
    /// Reason number.
    pub reason: u8,
    /// BLOCKED justification.
    pub justified: bool,
}

/// Run `pqsub-core`'s full audit on a case.
///
/// # Errors
/// Malformed hex fields only.
pub fn core_outcome(default_root: &str, c: &AuditCase) -> Result<AuditExpect> {
    let root = PublicKey::from_bytes(&hex::decode(c.root_pk.as_deref().unwrap_or(default_root))?)?;
    let opts = VerifyOptions {
        anchor: parse_anchor(&c.anchor)?,
        expected_head: c
            .expected_head
            .as_deref()
            .map(Hash32::from_hex)
            .transpose()?,
    };
    let res = Transcript::decode(&hex::decode(&c.transcript)?)
        .and_then(|t| audit(&root, &t, c.from, &opts));
    Ok(match res {
        Ok(r) => AuditExpect {
            ok: true,
            error: None,
            head: Some(r.trace.head.to_hex()),
            entry_hashes: r
                .trace
                .entries
                .iter()
                .map(|e| e.entry_hash.to_hex())
                .collect(),
            agent_ids: r.trace.entries.iter().map(|e| e.sender.to_hex()).collect(),
            findings: r
                .findings
                .iter()
                .map(|f| FindingV {
                    code: f.code.into(),
                    index: f.index,
                    call_index: f.call_index,
                    reason: f.reason,
                    justified: f.justified,
                })
                .collect(),
        },
        Err(e) => AuditExpect {
            ok: false,
            error: Some(e.code().into()),
            head: None,
            entry_hashes: vec![],
            agent_ids: vec![],
            findings: vec![],
        },
    })
}

/// `pqsub-core` evaluation of a caveat case: `None` if it does not decode.
#[must_use]
pub fn core_caveat(caveat: &[u8], tool: &str, args: &[u8]) -> Option<bool> {
    let c = Caveat::decode(caveat).ok()?;
    let v = cjson::parse_canonical(args, true).ok()?;
    if matches!(c.kind, CaveatKind::MaxCalls(_) | CaveatKind::Executor(_)) {
        return Some(true);
    }
    Some(c.holds(tool, &v, &Recipient::Role("x".into()), "x"))
}

fn seed(name: &str) -> [u8; 32] {
    payload_hash(format!("pqsub-v2-vector-seed/{name}").as_bytes()).0
}

/// `~` stands for a backslash in literals below (keeps escapes readable and literal).
fn esc(s: &str) -> Vec<u8> {
    s.replace('~', "\\").into_bytes()
}

fn cv(scope: Option<&str>, kind: CaveatKind) -> Caveat {
    Caveat {
        scope: scope.map_or(Scope::All, |t| Scope::Tool(t.into())),
        kind,
    }
}

fn js(s: &str) -> Vec<u8> {
    cjson::encode(&Value::Str(s.into()))
}

fn cjson_cases() -> Result<Vec<CjsonCase>> {
    let big_ok = {
        // {"k":"xxxx…"} of exactly 8192 bytes
        let pad = 8192 - br#"{"k":""}"#.len();
        format!(r#"{{"k":"{}"}}"#, "x".repeat(pad)).into_bytes()
    };
    let mut big_bad = big_ok.clone();
    big_bad.insert(7, b'x');
    let val_ok = format!(r#""{}""#, "y".repeat(1022)).into_bytes();
    let val_bad = format!(r#""{}""#, "y".repeat(1023)).into_bytes();
    let raw: Vec<(&str, Vec<u8>, bool, bool)> = vec![
        ("empty_object", b"{}".to_vec(), true, true),
        (
            "nested_types",
            br#"{"a":[1,-2,true,false,null,"s"],"b":{"c":{}}}"#.to_vec(),
            true,
            true,
        ),
        ("int_max", br#"{"a":9007199254740991}"#.to_vec(), true, true),
        (
            "int_min",
            br#"{"a":-9007199254740991}"#.to_vec(),
            true,
            true,
        ),
        (
            "int_over",
            br#"{"a":9007199254740992}"#.to_vec(),
            true,
            false,
        ),
        (
            "int_under",
            br#"{"a":-9007199254740992}"#.to_vec(),
            true,
            false,
        ),
        (
            "int_17_digits",
            br#"{"a":10000000000000000}"#.to_vec(),
            true,
            false,
        ),
        ("neg_zero", br#"{"a":-0}"#.to_vec(), true, false),
        ("leading_zero", br#"{"a":01}"#.to_vec(), true, false),
        ("float", br#"{"a":1.5}"#.to_vec(), true, false),
        ("exponent", br#"{"a":1e2}"#.to_vec(), true, false),
        ("plus_sign", br#"{"a":+1}"#.to_vec(), true, false),
        ("keys_sorted", br#"{"a":1,"b":2}"#.to_vec(), true, true),
        ("keys_unsorted", br#"{"b":1,"a":2}"#.to_vec(), true, false),
        ("dup_key", br#"{"a":1,"a":1}"#.to_vec(), true, false),
        (
            "utf16_order_ok",
            "{\"\u{1F600}\":1,\"\u{FF61}\":2}".as_bytes().to_vec(),
            true,
            true,
        ),
        (
            "utf16_order_bad",
            "{\"\u{FF61}\":2,\"\u{1F600}\":1}".as_bytes().to_vec(),
            true,
            false,
        ),
        ("whitespace_inner", br#"{"a": 1}"#.to_vec(), true, false),
        ("whitespace_outer", b" {}".to_vec(), true, false),
        ("trailing_newline", b"{}\n".to_vec(), true, false),
        (
            "escapes_canonical",
            esc(r#"{"s":"~"~~~b~f~n~r~t~u001f"}"#),
            true,
            true,
        ),
        ("escape_upper_hex", esc(r#"{"s":"~u001F"}"#), true, false),
        ("escape_printable", esc(r#"{"s":"~u0041"}"#), true, false),
        ("escape_solidus", esc(r#"{"s":"~/"}"#), true, false),
        (
            "escape_del_literal",
            "{\"s\":\"\u{7f}\"}".as_bytes().to_vec(),
            true,
            true,
        ),
        ("escape_del_escaped", esc(r#"{"s":"~u007f"}"#), true, false),
        ("raw_control", b"{\"s\":\"\x01\"}".to_vec(), true, false),
        (
            "non_ascii_literal",
            "{\"s\":\"é€😀\"}".as_bytes().to_vec(),
            true,
            true,
        ),
        ("non_ascii_escaped", esc(r#"{"s":"~u00e9"}"#), true, false),
        ("lone_high_surrogate", esc(r#"{"s":"~ud800"}"#), true, false),
        ("lone_low_surrogate", esc(r#"{"s":"~udc00"}"#), true, false),
        ("pair_escaped", esc(r#"{"s":"~ud83d~ude00"}"#), true, false),
        ("invalid_utf8", b"{\"s\":\"\xff\"}".to_vec(), true, false),
        ("depth_4", br#"{"a":[{"b":[]}]}"#.to_vec(), true, true),
        ("depth_5", br#"{"a":[{"b":[[]]}]}"#.to_vec(), true, false),
        ("array_top_args", b"[]".to_vec(), true, false),
        ("string_top_args", br#""x""#.to_vec(), true, false),
        ("args_8192", big_ok, true, true),
        ("args_8193", big_bad, true, false),
        ("value_scalar", b"42".to_vec(), false, true),
        ("value_string", br#""DE89""#.to_vec(), false, true),
        ("value_array_depth4", b"[[[[]]]]".to_vec(), false, true),
        ("value_array_depth5", b"[[[[[]]]]]".to_vec(), false, false),
        ("value_1024", val_ok, false, true),
        ("value_1025", val_bad, false, false),
        ("empty_input", b"".to_vec(), false, false),
        ("true_literal_bad", br#"{"a":tru}"#.to_vec(), true, false),
        ("trailing_comma", br#"{"a":1,}"#.to_vec(), true, false),
    ];
    let mut out = Vec::new();
    for (name, input, object, valid) in raw {
        let got = cjson::parse_canonical(&input, object).is_ok();
        if got != valid {
            bail!("cjson case {name}: intended {valid}, core says {got}");
        }
        out.push(CjsonCase {
            name: name.into(),
            input: hex::encode(input),
            object,
            valid,
        });
    }
    Ok(out)
}

fn caveat_cases() -> Result<Vec<CaveatCase>> {
    let path_under = cv(
        None,
        CaveatKind::PathUnder {
            path: "/p".into(),
            root: "/workspace".into(),
        },
    );
    let origin = cv(
        None,
        CaveatKind::UrlOrigin {
            path: "/u".into(),
            origins: vec![
                "https://acme.com:443".into(),
                "http://intranet.acme.com:8080".into(),
            ],
        },
    );
    let email = cv(
        None,
        CaveatKind::EmailDomain {
            path: "/to".into(),
            domains: vec!["acme.com".into()],
        },
    );
    let oneof = cv(
        Some("send_money"),
        CaveatKind::ArgOneOf {
            path: "/to".into(),
            values: vec![js("DE89LANDLORD"), b"[1,2]".to_vec()],
        },
    );
    let eq_obj = cv(
        None,
        CaveatKind::ArgEq {
            path: "/o".into(),
            value: br#"{"a":1,"b":[true]}"#.to_vec(),
        },
    );
    let range = cv(
        None,
        CaveatKind::IntRange {
            path: "/amount".into(),
            min: 1,
            max: 120_000,
        },
    );
    let allow = cv(
        None,
        CaveatKind::ToolAllow(vec!["get_balance".into(), "send_money".into()]),
    );
    let ptr = cv(
        None,
        CaveatKind::ArgEq {
            path: "/a~1b/~0c/1".into(),
            value: b"20".to_vec(),
        },
    );

    let obj = |k: &str, v: &str| format!("{{\"{k}\":{}}}", String::from_utf8_lossy(&js(v)));
    let mut ev: Vec<(&str, &Caveat, &str, String, bool)> = vec![
        (
            "path_inside",
            &path_under,
            "t",
            obj("p", "/workspace/a/b.txt"),
            true,
        ),
        (
            "path_root_itself",
            &path_under,
            "t",
            obj("p", "/workspace"),
            true,
        ),
        (
            "path_dotdot",
            &path_under,
            "t",
            obj("p", "/workspace/../etc/passwd"),
            false,
        ),
        (
            "path_sibling_prefix",
            &path_under,
            "t",
            obj("p", "/workspace-evil/x"),
            false,
        ),
        (
            "path_trailing_slash",
            &path_under,
            "t",
            obj("p", "/workspace/"),
            false,
        ),
        (
            "path_double_slash",
            &path_under,
            "t",
            obj("p", "/workspace//x"),
            false,
        ),
        (
            "path_dot",
            &path_under,
            "t",
            obj("p", "/workspace/./x"),
            false,
        ),
        (
            "path_relative",
            &path_under,
            "t",
            obj("p", "workspace/x"),
            false,
        ),
        (
            "path_backslash",
            &path_under,
            "t",
            obj("p", "/workspace/a\\b"),
            false,
        ),
        (
            "path_nul",
            &path_under,
            "t",
            obj("p", "/workspace/a\u{0}b"),
            false,
        ),
        (
            "path_not_string",
            &path_under,
            "t",
            r#"{"p":1}"#.into(),
            false,
        ),
        (
            "path_absent",
            &path_under,
            "t",
            r#"{"q":"/workspace"}"#.into(),
            false,
        ),
        (
            "url_ok",
            &origin,
            "t",
            obj("u", "https://acme.com/a?b#c"),
            true,
        ),
        (
            "url_explicit_default_port",
            &origin,
            "t",
            obj("u", "https://acme.com:443/x"),
            true,
        ),
        (
            "url_http_port",
            &origin,
            "t",
            obj("u", "http://intranet.acme.com:8080"),
            true,
        ),
        (
            "url_http_wrong_port",
            &origin,
            "t",
            obj("u", "http://intranet.acme.com"),
            false,
        ),
        (
            "url_suffix_attack",
            &origin,
            "t",
            obj("u", "https://acme.com.evil.com/"),
            false,
        ),
        (
            "url_userinfo",
            &origin,
            "t",
            obj("u", "https://evil@acme.com/"),
            false,
        ),
        (
            "url_userinfo_trick",
            &origin,
            "t",
            obj("u", "https://acme.com@evil.com/"),
            false,
        ),
        (
            "url_uppercase_host",
            &origin,
            "t",
            obj("u", "https://ACME.com/"),
            false,
        ),
        (
            "url_ipv4",
            &origin,
            "t",
            obj("u", "https://93.184.216.34/"),
            false,
        ),
        (
            "url_scheme_case",
            &origin,
            "t",
            obj("u", "HTTPS://acme.com/"),
            false,
        ),
        (
            "url_port_leading_zero",
            &origin,
            "t",
            obj("u", "https://acme.com:0443/"),
            false,
        ),
        (
            "url_query_first",
            &origin,
            "t",
            obj("u", "https://acme.com?x=@evil.com"),
            true,
        ),
        ("email_ok", &email, "t", obj("to", "bob@acme.com"), true),
        (
            "email_upper_domain",
            &email,
            "t",
            obj("to", "Bob@ACME.COM"),
            true,
        ),
        (
            "email_double_at",
            &email,
            "t",
            obj("to", "x@acme.com@evil.com"),
            false,
        ),
        (
            "email_subdomain",
            &email,
            "t",
            obj("to", "x@mail.acme.com"),
            false,
        ),
        (
            "email_suffix",
            &email,
            "t",
            obj("to", "x@evilacme.com"),
            false,
        ),
        (
            "email_empty_local",
            &email,
            "t",
            obj("to", "@acme.com"),
            false,
        ),
        ("email_space", &email, "t", obj("to", "a b@acme.com"), false),
        (
            "email_non_ascii",
            &email,
            "t",
            obj("to", "bé@acme.com"),
            false,
        ),
        (
            "oneof_match",
            &oneof,
            "send_money",
            obj("to", "DE89LANDLORD"),
            true,
        ),
        (
            "oneof_array_match",
            &oneof,
            "send_money",
            r#"{"to":[1,2]}"#.into(),
            true,
        ),
        (
            "oneof_miss",
            &oneof,
            "send_money",
            obj("to", "GB00ATTACKER"),
            false,
        ),
        (
            "oneof_scope_skip",
            &oneof,
            "get_balance",
            obj("to", "GB00ATTACKER"),
            true,
        ),
        (
            "eq_object",
            &eq_obj,
            "t",
            r#"{"o":{"a":1,"b":[true]}}"#.into(),
            true,
        ),
        (
            "eq_object_diff",
            &eq_obj,
            "t",
            r#"{"o":{"a":1,"b":[false]}}"#.into(),
            false,
        ),
        ("range_in", &range, "t", r#"{"amount":120000}"#.into(), true),
        (
            "range_over",
            &range,
            "t",
            r#"{"amount":120001}"#.into(),
            false,
        ),
        (
            "range_string",
            &range,
            "t",
            r#"{"amount":"5"}"#.into(),
            false,
        ),
        ("allow_in", &allow, "send_money", "{}".into(), true),
        ("allow_out", &allow, "send_email", "{}".into(), false),
        (
            "pointer_escapes",
            &ptr,
            "t",
            r#"{"a/b":{"~c":[10,20]}}"#.into(),
            true,
        ),
        (
            "pointer_index_oob",
            &ptr,
            "t",
            r#"{"a/b":{"~c":[10]}}"#.into(),
            false,
        ),
    ];
    let mut out = Vec::new();
    for (name, c, tool, args, holds) in ev.drain(..) {
        let enc = c.encode()?;
        let got = core_caveat(&enc, tool, args.as_bytes());
        if got != Some(holds) {
            bail!("caveat case {name}: intended {holds}, core says {got:?}");
        }
        out.push(CaveatCase {
            name: name.into(),
            caveat: hex::encode(enc),
            decode_ok: true,
            tool: tool.into(),
            args: hex::encode(args),
            holds: Some(holds),
        });
    }
    // Decode failures (hand-built bytes).
    let p = |s: &str| {
        let mut v = vec![s.len() as u8];
        v.extend_from_slice(s.as_bytes());
        v
    };
    let mut bad: Vec<(&str, Vec<u8>)> = vec![
        (
            "toolallow_scoped",
            [vec![1, 1], p("send_money"), vec![1], p("a")].concat(),
        ),
        ("toolallow_bad_name", [vec![1, 0, 1], p("Send")].concat()),
        ("toolallow_empty", vec![1, 0, 0]),
        ("unknown_type", vec![10, 0]),
        (
            "bad_scope_tag",
            [vec![8, 2], 1u32.to_be_bytes().to_vec()].concat(),
        ),
        (
            "argeq_noncanonical",
            [
                vec![2, 0],
                p("/a"),
                3u16.to_be_bytes().to_vec(),
                b"{ }".to_vec(),
            ]
            .concat(),
        ),
        (
            "argeq_bad_pointer",
            [
                vec![2, 0],
                p("/a~2"),
                1u16.to_be_bytes().to_vec(),
                b"1".to_vec(),
            ]
            .concat(),
        ),
        (
            "argeq_pointer_no_slash",
            [
                vec![2, 0],
                p("a"),
                1u16.to_be_bytes().to_vec(),
                b"1".to_vec(),
            ]
            .concat(),
        ),
        (
            "range_inverted",
            [
                vec![4, 0],
                p("/a"),
                5i64.to_be_bytes().to_vec(),
                4i64.to_be_bytes().to_vec(),
            ]
            .concat(),
        ),
        (
            "pathunder_trailing_slash_root",
            [
                vec![5, 0],
                p("/a"),
                4u16.to_be_bytes().to_vec(),
                b"/ws/".to_vec(),
            ]
            .concat(),
        ),
        (
            "origin_no_port",
            [vec![6, 0], p("/u"), vec![1], p("https://acme.com")].concat(),
        ),
        (
            "origin_port_zero_pad",
            [vec![6, 0], p("/u"), vec![1], p("https://acme.com:0443")].concat(),
        ),
        (
            "email_domain_upper",
            [vec![7, 0], p("/to"), vec![1], p("ACME.com")].concat(),
        ),
        (
            "maxcalls_zero",
            [vec![8, 0], 0u32.to_be_bytes().to_vec()].concat(),
        ),
        ("executor_empty", vec![9, 0, 0]),
        (
            "trailing_byte",
            [cv(None, CaveatKind::MaxCalls(1)).encode()?, vec![0]].concat(),
        ),
        (
            "truncated",
            cv(None, CaveatKind::MaxCalls(1)).encode()?[..5].to_vec(),
        ),
    ];
    for (name, b) in bad.drain(..) {
        if Caveat::decode(&b).is_ok() {
            bail!("caveat case {name}: intended decode failure");
        }
        out.push(CaveatCase {
            name: name.into(),
            caveat: hex::encode(b),
            decode_ok: false,
            tool: "t".into(),
            args: hex::encode(b"{}"),
            holds: None,
        });
    }
    Ok(out)
}

struct World {
    root: AgentKeypair,
    principal: AgentKeypair,
    orch: AgentKeypair,
    agent: AgentKeypair,
    bank: AgentKeypair,
    mail: AgentKeypair,
    ids: Vec<IdentityDocument>,
    g: Vec<Grant>,
}

fn grant(
    issuer: &AgentKeypair,
    aud: &AgentKeypair,
    parent: Hash32,
    depth: u8,
    until: u64,
    caveats: Vec<Caveat>,
) -> Result<Grant> {
    let spec = GrantSpec {
        audience: aud.agent_id(),
        parent,
        not_before_ms: T0,
        not_after_ms: until,
        depth,
        nonce: [depth; 16],
        caveats,
    };
    Ok(Grant::issue(issuer, spec, DET)?)
}

fn world() -> Result<World> {
    let k = |n: &str| AgentKeypair::from_seed(&seed(n));
    let (root, principal, orch, agent, bank, mail) = (
        k("root")?,
        k("principal")?,
        k("orchestrator")?,
        k("agent")?,
        k("bank")?,
        k("mail")?,
    );
    let id = |a: &AgentKeypair, n: &str, r: &str| {
        let c = IdentityClaims {
            name: n.into(),
            role: r.into(),
            not_before_ms: T0,
            not_after_ms: T0 + 365 * 1440 * MIN,
        };
        IdentityDocument::issue(&root, a.public_key(), c, DET)
    };
    let ids = vec![
        id(&principal, "principal", "principal")?,
        id(&orch, "orchestrator", "orchestrator")?,
        id(&agent, "agent", "worker")?,
        id(&bank, "bank", "bank")?,
        id(&mail, "mail", "mail")?,
    ];
    let g0 = grant(
        &root,
        &principal,
        Hash32::ZERO,
        3,
        T0 + 365 * 1440 * MIN,
        vec![cv(
            None,
            CaveatKind::ToolAllow(vec![
                "get_balance".into(),
                "send_email".into(),
                "send_money".into(),
            ]),
        )],
    )?;
    let g1 = grant(
        &principal,
        &orch,
        g0.id(),
        2,
        T0 + 30 * MIN,
        vec![
            cv(
                Some("send_money"),
                CaveatKind::ArgOneOf {
                    path: "/to".into(),
                    values: vec![js("DE89LANDLORD")],
                },
            ),
            cv(
                Some("send_money"),
                CaveatKind::IntRange {
                    path: "/amount".into(),
                    min: 1,
                    max: 120_000,
                },
            ),
            cv(
                Some("send_money"),
                CaveatKind::Executor(vec!["bank".into()]),
            ),
            cv(Some("send_money"), CaveatKind::MaxCalls(2)),
            cv(
                Some("send_email"),
                CaveatKind::EmailDomain {
                    path: "/to".into(),
                    domains: vec!["acme.com".into()],
                },
            ),
            cv(
                Some("send_email"),
                CaveatKind::Executor(vec!["mail".into()]),
            ),
        ],
    )?;
    let g2 = grant(
        &orch,
        &agent,
        g1.id(),
        1,
        T0 + 30 * MIN,
        vec![cv(
            None,
            CaveatKind::ToolAllow(vec![
                "get_balance".into(),
                "send_email".into(),
                "send_money".into(),
            ]),
        )],
    )?;
    Ok(World {
        root,
        principal,
        orch,
        agent,
        bank,
        mail,
        ids,
        g: vec![g0, g1, g2],
    })
}

struct Tb<'w> {
    w: &'w World,
    tb: TraceBuilder,
}

impl Tb<'_> {
    fn call(
        &mut self,
        who: &AgentKeypair,
        exec: &str,
        tool: &str,
        args: &str,
        chain: Vec<Hash32>,
        ts: u64,
    ) -> Result<SignedManifest> {
        let spec = EntrySpec {
            kind: ManifestKind::ToolCall,
            recipient: Recipient::Role(exec.into()),
            intent: format!("call {tool}"),
            payload_hash: None,
            timestamp_ms: ts,
        };
        let ext = Ext::ToolCall(ToolCall {
            tool: tool.into(),
            args: args.as_bytes().to_vec(),
            chain,
        });
        Ok(self.tb.append_ext(who, spec, ext, DET)?.clone())
    }
    fn rcpt(
        &mut self,
        by: &AgentKeypair,
        c: &SignedManifest,
        out: Outcome<'_>,
        ts: u64,
    ) -> Result<()> {
        let spec = EntrySpec {
            kind: ManifestKind::Receipt,
            recipient: Recipient::Agent(c.body().sender),
            intent: "receipt".into(),
            payload_hash: None,
            timestamp_ms: ts,
        };
        self.tb.append_ext(by, spec, receipt_ext(c, out)?, DET)?;
        Ok(())
    }
    fn chain(&self) -> Vec<Hash32> {
        self.w.g.iter().map(Grant::id).collect()
    }
    fn done(self, grants: Vec<Grant>) -> Result<Vec<u8>> {
        Ok(Transcript {
            identities: self.w.ids.clone(),
            grants,
            entries: self.tb.into_entries(),
        }
        .encode()?)
    }
}

const PAY: &str = r#"{"amount":95000,"to":"DE89LANDLORD"}"#;
const ATTACK: &str = r#"{"amount":5000,"to":"GB00ATTACKER"}"#;

fn main_trace(w: &World) -> Result<(Vec<u8>, Vec<SignedManifest>)> {
    let mut t = Tb {
        w,
        tb: TraceBuilder::new(),
    };
    let ts = T0 + MIN;
    t.tb.append_ext(
        &w.orch,
        EntrySpec {
            kind: ManifestKind::Handoff,
            recipient: Recipient::Agent(w.agent.agent_id()),
            intent: "Pay rent; notify landlord".into(),
            payload_hash: None,
            timestamp_ms: ts,
        },
        Ext::V2,
        DET,
    )?;
    let c = t.call(&w.agent, "bank", "send_money", PAY, t.chain(), ts + 1)?;
    t.rcpt(&w.bank, &c, Outcome::Ok(b"tx-1"), ts + 2)?;
    let a = t.call(&w.agent, "bank", "send_money", ATTACK, t.chain(), ts + 3)?;
    t.rcpt(
        &w.bank,
        &a,
        Outcome::Refused(Denial::CaveatViolation),
        ts + 4,
    )?;
    let m = t.call(
        &w.agent,
        "mail",
        "send_email",
        r#"{"body":"Rent paid","to":"landlord@acme.com"}"#,
        t.chain(),
        ts + 5,
    )?;
    t.rcpt(&w.mail, &m, Outcome::Ok(b"msg-1"), ts + 6)?;
    let x = t.call(
        &w.agent,
        "mail",
        "send_email",
        r#"{"body":"exfil","to":"x@evil.com"}"#,
        t.chain(),
        ts + 7,
    )?;
    t.rcpt(
        &w.mail,
        &x,
        Outcome::Refused(Denial::CaveatViolation),
        ts + 8,
    )?;
    t.call(&w.agent, "bank", "get_balance", "{}", t.chain(), ts + 9)?;
    let entries = t.tb.entries().to_vec();
    Ok((t.done(w.g.clone())?, entries))
}

fn container_v2(ids: &[Vec<u8>], grants: &[Vec<u8>], ents: &[Vec<u8>]) -> Vec<u8> {
    let mut v = b"PQST\x02".to_vec();
    v.extend_from_slice(&(ids.len() as u16).to_be_bytes());
    for d in ids {
        v.extend_from_slice(&(d.len() as u32).to_be_bytes());
        v.extend_from_slice(d);
    }
    v.extend_from_slice(&(grants.len() as u16).to_be_bytes());
    for g in grants {
        v.extend_from_slice(&(g.len() as u32).to_be_bytes());
        v.extend_from_slice(g);
    }
    v.extend_from_slice(&(ents.len() as u32).to_be_bytes());
    for e in ents {
        v.extend_from_slice(&(e.len() as u32).to_be_bytes());
        v.extend_from_slice(e);
    }
    v
}

#[allow(clippy::too_many_lines)]
fn audit_cases(w: &World) -> Result<Vec<(AuditCase, Expect)>> {
    let mut out = Vec::new();
    let mut add = |name: &str,
                   desc: &str,
                   tr: Vec<u8>,
                   from: usize,
                   anchor: String,
                   eh: Option<Hash32>,
                   want: Expect| {
        out.push((
            AuditCase {
                name: name.into(),
                description: desc.into(),
                root_pk: None,
                transcript: hex::encode(tr),
                from,
                anchor,
                expected_head: eh.map(|h| h.to_hex()),
                expect: AuditExpect {
                    ok: false,
                    error: None,
                    head: None,
                    entry_hashes: vec![],
                    agent_ids: vec![],
                    findings: vec![],
                },
            },
            want,
        ));
    };
    let g = || "genesis".to_string();
    let ts = T0 + MIN;

    let (main, entries) = main_trace(w)?;
    let head = entries
        .last()
        .map(SignedManifest::entry_hash)
        .unwrap_or_default();
    add("main_full", "handoff, legit payment, blocked payment attack, legit email, blocked exfil email, unreceipted call", main.clone(), 0, g(), Some(head),
        Expect::Ok(vec![f("BLOCKED", 4, 3, 6, true), f("BLOCKED", 8, 7, 6, true), f("NO_RECEIPT", 9, 9, 0, false)]));
    add(
        "main_suffix_anchored",
        "window entries[3..] anchored at hash(entry 2)",
        main.clone(),
        3,
        entries[2].entry_hash().to_hex(),
        None,
        Expect::Ok(vec![
            f("BLOCKED", 1, 0, 6, true),
            f("BLOCKED", 5, 4, 6, true),
            f("NO_RECEIPT", 6, 6, 0, false),
        ]),
    );
    add(
        "orphan_receipt",
        "window starts at a receipt whose call is outside it",
        main.clone(),
        2,
        "none".into(),
        None,
        Expect::Err("RECEIPT_ORPHAN"),
    );

    // Malicious/buggy executor runs the attack.
    let mut t = Tb {
        w,
        tb: TraceBuilder::new(),
    };
    let a = t.call(&w.agent, "bank", "send_money", ATTACK, t.chain(), ts)?;
    t.rcpt(&w.bank, &a, Outcome::Ok(b"tx-evil"), ts + 1)?;
    add(
        "executed_caveat_violation",
        "executor ran a call violating ArgOneOf",
        t.done(w.g.clone())?,
        0,
        g(),
        None,
        Expect::Ok(vec![f("EXECUTED_UNAUTHORIZED", 1, 0, 6, false)]),
    );

    let mut t = Tb {
        w,
        tb: TraceBuilder::new(),
    };
    let c = t.call(&w.agent, "bank", "get_balance", "{}", t.chain(), ts)?;
    t.rcpt(&w.bank, &c, Outcome::Ok(b"1"), T0 + 31 * MIN)?;
    add(
        "executed_after_expiry",
        "receipt time (executor clock) after grant expiry; caller timestamp inside",
        t.done(w.g.clone())?,
        0,
        g(),
        None,
        Expect::Ok(vec![f("EXECUTED_UNAUTHORIZED", 1, 0, 5, false)]),
    );

    let mut t = Tb {
        w,
        tb: TraceBuilder::new(),
    };
    for i in 0..3u64 {
        let c = t.call(&w.agent, "bank", "send_money", PAY, t.chain(), ts + 2 * i)?;
        t.rcpt(&w.bank, &c, Outcome::Ok(b"tx"), ts + 2 * i + 1)?;
    }
    add(
        "budget_exceeded",
        "third send_money beyond MaxCalls 2 executed anyway",
        t.done(w.g.clone())?,
        0,
        g(),
        None,
        Expect::Ok(vec![f("EXECUTED_UNAUTHORIZED", 5, 4, 7, false)]),
    );

    let mut t = Tb {
        w,
        tb: TraceBuilder::new(),
    };
    let c = t.call(&w.agent, "bank", "send_money", PAY, t.chain(), ts)?;
    t.rcpt(&w.bank, &c, Outcome::Error(b"insufficient funds"), ts + 1)?;
    let c = t.call(&w.agent, "bank", "send_money", PAY, t.chain(), ts + 2)?;
    t.rcpt(
        &w.bank,
        &c,
        Outcome::Refused(Denial::CaveatViolation),
        ts + 3,
    )?;
    add(
        "unjustified_refusal",
        "executed-error counts toward budget; then a valid call refused (BLOCKED, justified=false)",
        t.done(w.g.clone())?,
        0,
        g(),
        None,
        Expect::Ok(vec![f("BLOCKED", 3, 2, 6, false)]),
    );

    let mut t = Tb {
        w,
        tb: TraceBuilder::new(),
    };
    let mut ch = t.chain();
    ch[1] = Hash32([7; 32]);
    let c = t.call(&w.agent, "bank", "get_balance", "{}", ch, ts)?;
    t.rcpt(&w.bank, &c, Outcome::Ok(b"1"), ts + 1)?;
    add(
        "grant_unknown",
        "chain references a grant not in the transcript",
        t.done(w.g.clone())?,
        0,
        g(),
        None,
        Expect::Ok(vec![f("EXECUTED_UNAUTHORIZED", 1, 0, 2, false)]),
    );

    let mut genc = w.g[2].encode();
    genc[4 + 1 + 96 + 16 + 1] ^= 1; // nonce byte
    let tampered = Grant::decode(&genc)?;
    let mut t = Tb {
        w,
        tb: TraceBuilder::new(),
    };
    let c = t.call(
        &w.agent,
        "bank",
        "get_balance",
        "{}",
        vec![w.g[0].id(), w.g[1].id(), tampered.id()],
        ts,
    )?;
    t.rcpt(&w.bank, &c, Outcome::Ok(b"1"), ts + 1)?;
    add(
        "grant_tampered",
        "leaf grant modified after signing",
        t.done(vec![w.g[0].clone(), w.g[1].clone(), tampered])?,
        0,
        g(),
        None,
        Expect::Ok(vec![f("EXECUTED_UNAUTHORIZED", 1, 0, 3, false)]),
    );

    let fake = grant(
        &w.principal,
        &w.agent,
        Hash32::ZERO,
        3,
        T0 + 30 * MIN,
        vec![],
    )?;
    let mut t = Tb {
        w,
        tb: TraceBuilder::new(),
    };
    let c = t.call(&w.agent, "bank", "send_money", ATTACK, vec![fake.id()], ts)?;
    t.rcpt(&w.bank, &c, Outcome::Ok(b"tx"), ts + 1)?;
    add(
        "grant_chain_fake_root",
        "chain starts at a grant not issued by the root",
        t.done(vec![w.g[0].clone(), fake])?,
        0,
        g(),
        None,
        Expect::Ok(vec![f("EXECUTED_UNAUTHORIZED", 1, 0, 4, false)]),
    );

    let skip = grant(&w.agent, &w.agent, w.g[0].id(), 0, T0 + 30 * MIN, vec![])?;
    let mut t = Tb {
        w,
        tb: TraceBuilder::new(),
    };
    let c = t.call(
        &w.agent,
        "bank",
        "send_money",
        ATTACK,
        vec![w.g[0].id(), skip.id()],
        ts,
    )?;
    t.rcpt(&w.bank, &c, Outcome::Ok(b"tx"), ts + 1)?;
    add(
        "grant_chain_skip",
        "agent self-issues a grant under the principal's grant",
        t.done(vec![w.g[0].clone(), skip])?,
        0,
        g(),
        None,
        Expect::Ok(vec![f("EXECUTED_UNAUTHORIZED", 1, 0, 4, false)]),
    );

    let sub = grant(&w.agent, &w.agent, w.g[2].id(), 0, T0 + 30 * MIN, vec![])?;
    let mut all = w.g.clone();
    all.push(sub.clone());
    let mut t = Tb {
        w,
        tb: TraceBuilder::new(),
    };
    let mut ch = t.chain();
    ch.push(sub.id());
    let c = t.call(&w.agent, "bank", "send_money", ATTACK, ch.clone(), ts)?;
    t.rcpt(&w.bank, &c, Outcome::Ok(b"tx"), ts + 1)?;
    let c = t.call(&w.agent, "bank", "send_money", PAY, ch, ts + 2)?;
    t.rcpt(&w.bank, &c, Outcome::Ok(b"tx"), ts + 3)?;
    add(
        "subgrant_cannot_widen",
        "caveat-free self sub-grant: attack still unauthorized, legit call authorized",
        t.done(all)?,
        0,
        g(),
        None,
        Expect::Ok(vec![f("EXECUTED_UNAUTHORIZED", 1, 0, 6, false)]),
    );

    let mut t = Tb {
        w,
        tb: TraceBuilder::new(),
    };
    let c = t.call(
        &w.agent,
        "mail",
        "send_email",
        r#"{"to":"a@acme.com"}"#,
        t.chain(),
        ts,
    )?;
    t.rcpt(&w.mail, &c, Outcome::Ok(b"1"), ts + 1)?;
    let c = t.call(&w.agent, "mail", "send_money", PAY, t.chain(), ts + 2)?;
    t.rcpt(&w.mail, &c, Outcome::Ok(b"1"), ts + 3)?;
    add(
        "executor_caveat",
        "send_money executed by the mail executor (Executor caveat requires bank)",
        t.done(w.g.clone())?,
        0,
        g(),
        None,
        Expect::Ok(vec![f("EXECUTED_UNAUTHORIZED", 3, 2, 6, false)]),
    );

    let mut t = Tb {
        w,
        tb: TraceBuilder::new(),
    };
    let c = t.call(&w.agent, "bank", "get_balance", "{}", t.chain(), ts)?;
    t.rcpt(&w.mail, &c, Outcome::Ok(b"1"), ts + 1)?;
    add(
        "receipt_wrong_executor",
        "mail signs a receipt for a call addressed to bank",
        t.done(w.g.clone())?,
        0,
        g(),
        None,
        Expect::Err("RECEIPT_WRONG_EXECUTOR"),
    );

    let mut t = Tb {
        w,
        tb: TraceBuilder::new(),
    };
    let c = t.call(&w.agent, "bank", "get_balance", "{}", t.chain(), ts)?;
    t.rcpt(&w.bank, &c, Outcome::Ok(b"1"), ts + 1)?;
    t.rcpt(&w.bank, &c, Outcome::Ok(b"1"), ts + 2)?;
    add(
        "duplicate_receipt",
        "two receipts for one call",
        t.done(w.g.clone())?,
        0,
        g(),
        None,
        Expect::Err("DUPLICATE_RECEIPT"),
    );

    // Byte-level corruptions of the main trace.
    let id_enc: Vec<Vec<u8>> = w.ids.iter().map(IdentityDocument::encode).collect();
    let g_enc: Vec<Vec<u8>> = w.g.iter().map(Grant::encode).collect();
    let en: Vec<Vec<u8>> = entries.iter().map(SignedManifest::encode).collect();
    let find = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).position(|x| x == needle);

    let mut e = en.clone();
    let p = find(&e[3], b"GB00ATTACKER").unwrap_or(0);
    e[3][p + 2] ^= 1;
    add(
        "tamper_call_args",
        "bit flip inside signed tool-call args (still canonical)",
        container_v2(&id_enc, &g_enc, &e),
        0,
        g(),
        None,
        Expect::Err("BAD_SIGNATURE"),
    );
    let mut e = en.clone();
    let p = find(&e[1], b"{\"amount\":95000,\"to\":\"DE89LANDLORD\"}").unwrap_or(0);
    e[1].splice(
        p..p + PAY.len(),
        br#"{"to":"DE89LANDLORD","amount":95000}"#.iter().copied(),
    );
    add(
        "noncanonical_args",
        "tool-call args with unsorted keys",
        container_v2(&id_enc, &g_enc, &e),
        0,
        g(),
        None,
        Expect::Err("DECODE"),
    );
    let mut e = en.clone();
    let n = e[2].len();
    e[2][n - SIGNATURE_LEN - 34] = 2; // status ok -> refused, reason stays 0
    add(
        "receipt_bad_reason",
        "receipt status refused with reason 0",
        container_v2(&id_enc, &g_enc, &e),
        0,
        g(),
        None,
        Expect::Err("DECODE"),
    );
    let mut e = en.clone();
    let n = e[2].len();
    e[2][n - 100] ^= 4;
    add(
        "tamper_receipt_sig",
        "bit flip in a receipt signature",
        container_v2(&id_enc, &g_enc, &e),
        0,
        g(),
        None,
        Expect::Err("BAD_SIGNATURE"),
    );
    let mut gd = g_enc.clone();
    gd.push(g_enc[0].clone());
    add(
        "duplicate_grant",
        "same grant twice in the grants section",
        container_v2(&id_enc, &gd, &en),
        0,
        g(),
        None,
        Expect::Err("DECODE"),
    );
    let mut ge = g_enc.clone();
    let n = ge[1].len();
    ge[1][n - 50] ^= 1;
    add(
        "tamper_grant_sig",
        "bit flip in g1's signature: every executed call becomes unauthorized",
        container_v2(&id_enc, &ge, &en),
        0,
        g(),
        None,
        Expect::Ok(vec![
            f("EXECUTED_UNAUTHORIZED", 2, 1, 3, false),
            f("BLOCKED", 4, 3, 6, true),
            f("EXECUTED_UNAUTHORIZED", 6, 5, 3, false),
            f("BLOCKED", 8, 7, 6, true),
            f("NO_RECEIPT", 9, 9, 0, false),
        ]),
    );

    // MaxCalls without Executor: hand-built, root-signed grant.
    let mut body = b"PQSG\x01".to_vec();
    body.extend_from_slice(&w.root.agent_id().0);
    body.extend_from_slice(&w.principal.agent_id().0);
    body.extend_from_slice(&[0u8; 32]);
    body.extend_from_slice(&T0.to_be_bytes());
    body.extend_from_slice(&(T0 + MIN).to_be_bytes());
    body.extend_from_slice(&[1u8]);
    body.extend_from_slice(&[0u8; 16]);
    body.push(1);
    body.extend_from_slice(&cv(None, CaveatKind::MaxCalls(1)).encode()?);
    let sig = w.root.sign(&body, CTX_GRANT, DET)?;
    body.extend_from_slice(&sig[..]);
    add(
        "grant_maxcalls_without_executor",
        "validly signed grant violating the MaxCalls/Executor rule",
        container_v2(&id_enc, &[body], &en[..1]),
        0,
        g(),
        None,
        Expect::Err("DECODE"),
    );

    let v1_entry = {
        let mut tb = TraceBuilder::new();
        tb.append(
            &w.orch,
            EntrySpec {
                kind: ManifestKind::Handoff,
                recipient: Recipient::Role("x".into()),
                intent: "v1".into(),
                payload_hash: None,
                timestamp_ms: ts,
            },
            DET,
        )?;
        tb.entries()[0].encode()
    };
    add(
        "v2_container_v1_only",
        "v2 container with no grants and only v1 manifests (non-canonical)",
        container_v2(&id_enc, &[], std::slice::from_ref(&v1_entry)),
        0,
        g(),
        None,
        Expect::Err("DECODE"),
    );
    let mut v1c = b"PQST\x01".to_vec();
    v1c.extend_from_slice(&(id_enc.len() as u16).to_be_bytes());
    for d in &id_enc {
        v1c.extend_from_slice(&(d.len() as u32).to_be_bytes());
        v1c.extend_from_slice(d);
    }
    v1c.extend_from_slice(&1u32.to_be_bytes());
    v1c.extend_from_slice(&(en[0].len() as u32).to_be_bytes());
    v1c.extend_from_slice(&en[0]);
    add(
        "v1_container_v2_entry",
        "v1 container holding a v2 manifest",
        v1c,
        0,
        g(),
        None,
        Expect::Err("DECODE"),
    );
    add(
        "mixed_v1_v2_ok",
        "v2 container with grants mixing a v1 handoff and v2 entries",
        container_v2(&id_enc, &g_enc, &[v1_entry]),
        0,
        g(),
        None,
        Expect::Ok(vec![]),
    );
    Ok(out)
}

enum Expect {
    Ok(Vec<FindingV>),
    Err(&'static str),
}

fn f(code: &str, index: usize, call_index: usize, reason: u8, justified: bool) -> FindingV {
    FindingV {
        code: code.into(),
        index,
        call_index,
        reason,
        justified,
    }
}

/// Generate all v2 vectors.
///
/// # Errors
/// If `pqsub-core` disagrees with any intended outcome.
pub fn generate() -> Result<VectorsV2> {
    let w = world()?;
    let root_hex = hex::encode(w.root.public_key().as_bytes());
    let mut cases = Vec::new();
    for (mut c, want) in audit_cases(&w)? {
        let got = core_outcome(&root_hex, &c)?;
        let ok = match &want {
            Expect::Ok(fs) => got.ok && got.findings == *fs,
            Expect::Err(code) => got.error.as_deref() == Some(*code),
        };
        if !ok {
            bail!("audit case {}: core produced {:?}", c.name, got);
        }
        c.expect = got;
        cases.push(c);
    }
    Ok(VectorsV2 {
        format: "pqsub-test-vectors/v2".into(),
        root_pk: root_hex,
        cjson: cjson_cases()?,
        caveats: caveat_cases()?,
        cases,
    })
}

/// Pretty JSON with trailing newline.
///
/// # Errors
/// Serialization failure.
pub fn to_json(v: &VectorsV2) -> Result<String> {
    Ok(serde_json::to_string_pretty(v)? + "\n")
}
