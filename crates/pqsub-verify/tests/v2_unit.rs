//! v2 unit tests for the independent verifier (no pqsub-core).

use std::collections::HashMap;

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer};
use pqsub_verify::cjson::{self, Value};
use pqsub_verify::{
    audit_transcript, caveat_eval, cjson_valid, hd, verify_transcript, Anchor, Finding,
};

// ------------------------------------------------------------------ cjson

#[test]
fn cjson_accepts_canonical() {
    let ok_obj: &[&[u8]] = &[
        b"{}",
        b"{\"a\":1}",
        b"{\"a\":[1,2,{\"b\":null}],\"b\":true,\"c\":false}",
        b"{\"a\":\"\\u001f\"}",
        b"{\"a\":\"\\b\\f\\n\\r\\t\\\"\\\\\"}",
        b"{\"a\":\"/\"}",
        b"{\"a\":\"\x7f\"}",
        "{\"a\":\"\u{e9}\u{1F600}\"}".as_bytes(),
        b"{\"a\":9007199254740991}",
        b"{\"a\":-9007199254740991}",
        b"{\"a\":0}",
        b"{\"a\":-1}",
        b"{\"a\":{\"b\":{\"c\":{\"d\":1}}}}",
        b"{\"\":0}",
        // UTF-16 order: U+1F600 (D83D DE00) sorts before U+FF61 (FF61).
        "{\"\u{1F600}\":1,\"\u{FF61}\":2}".as_bytes(),
        b"{\"A\":1,\"a\":2,\"aa\":3,\"b\":4}",
    ];
    for c in ok_obj {
        assert!(cjson_valid(c, true), "{}", String::from_utf8_lossy(c));
        assert!(
            c.len() > 1024 || cjson_valid(c, false),
            "{}",
            String::from_utf8_lossy(c)
        );
    }
    for c in [
        &b"1"[..],
        b"-5",
        b"\"x\"",
        b"true",
        b"null",
        b"[]",
        b"[[[[1]]]]",
    ] {
        assert!(cjson_valid(c, false), "{}", String::from_utf8_lossy(c));
        assert!(!cjson_valid(c, true), "top-level non-object as args");
    }
}

#[test]
fn cjson_rejects_noncanonical() {
    let bad: &[&[u8]] = &[
        b"",
        b"{",
        b"{}x",
        b"{} ",
        b" {}",
        b"{ \"a\":1}",
        b"{\"a\": 1}",
        b"{\"a\":1,}",
        b"{\"b\":1,\"a\":2}",
        b"{\"a\":1,\"a\":1}",
        b"{\"a\":1,\"a\":2}",
        b"{\"a\":-0}",
        b"{\"a\":01}",
        b"{\"a\":+1}",
        b"{\"a\":1.0}",
        b"{\"a\":1e2}",
        b"{\"a\":1E2}",
        b"{\"a\":9007199254740992}",
        b"{\"a\":-9007199254740992}",
        b"{\"a\":99999999999999999999999999}",
        b"{\"a\":\"\\u001F\"}",
        b"{\"a\":\"\\/\"}",
        b"{\"a\":\"\\u0041\"}",
        b"{\"a\":\"\\u00e9\"}",
        b"{\"a\":\"\\u007f\"}",
        b"{\"a\":\"\\u000a\"}",
        b"{\"a\":\"\\ud800\"}",
        b"{\"a\":\"\\udc00\"}",
        b"{\"a\":\"\\ud83d\\ude00\"}",
        b"{\"a\":\"\\ud83dx\"}",
        b"{\"a\":\"\n\"}",
        b"{\"a\":\"\x01\"}",
        b"{\"a\":\"\xff\"}",
        b"{\"a\":\"\\x\"}",
        b"{\"a\":{\"b\":{\"c\":{\"d\":{}}}}}",
        b"{\"a\":[[[[1]]]]}",
        b"{\"a\":TRUE}",
        b"{\"a\":nul}",
        b"{\"a\":'x'}",
        b"{a:1}",
        "{\"\u{FF61}\":2,\"\u{1F600}\":1}".as_bytes(),
    ];
    for c in bad {
        assert!(!cjson_valid(c, true), "{}", String::from_utf8_lossy(c));
    }
    for c in [
        &b"-0"[..],
        b"[[[[[1]]]]]",
        b" 1",
        b"1 ",
        b"00",
        b"\"\\u0020\"",
    ] {
        assert!(!cjson_valid(c, false), "{}", String::from_utf8_lossy(c));
    }
}

#[test]
fn cjson_size_limits() {
    let s = |n: usize| format!("\"{}\"", "a".repeat(n - 2)).into_bytes();
    assert!(cjson_valid(&s(1024), false));
    assert!(!cjson_valid(&s(1025), false));
    let o = |n: usize| format!("{{\"a\":\"{}\"}}", "a".repeat(n - 8)).into_bytes();
    assert_eq!(o(8192).len(), 8192);
    assert!(cjson_valid(&o(8192), true));
    assert!(!cjson_valid(&o(8193), true));
}

// ------------------------------------------------------------------ pointer

#[test]
fn pointer_rfc6901() {
    let doc = cjson::parse(
        b"{\"\":0,\"a/b\":1,\"arr\":[10,20],\"m~n\":2,\"o\":{\"k\":\"v\"},\"~1\":3}",
        true,
    )
    .expect("doc");
    let get = |p: &str| cjson::pointer(&doc, p).cloned();
    assert_eq!(get(""), Some(doc.clone()));
    assert_eq!(get("/"), Some(Value::Int(0)));
    assert_eq!(get("/a~1b"), Some(Value::Int(1)));
    assert_eq!(get("/m~0n"), Some(Value::Int(2)));
    assert_eq!(get("/~01"), Some(Value::Int(3)));
    assert_eq!(get("/arr/0"), Some(Value::Int(10)));
    assert_eq!(get("/arr/1"), Some(Value::Int(20)));
    assert_eq!(get("/o/k"), Some(Value::Str("v".into())));
    for absent in [
        "/arr/2",
        "/arr/01",
        "/arr/-",
        "/arr/+1",
        "/arr/ 1",
        "/arr/99999999999999999999999999",
        "/o/k/x",
        "/o/K",
        "/a/b",
        "/missing",
        "/arr/0/x",
    ] {
        assert_eq!(get(absent), None, "{absent}");
    }
    assert!(cjson::valid_pointer(""));
    assert!(cjson::valid_pointer("/a~0~1"));
    assert!(!cjson::valid_pointer("a"));
    assert!(!cjson::valid_pointer("/a~2"));
    assert!(!cjson::valid_pointer("/a~"));
}

// ------------------------------------------------------------------ caveat encoders

fn str8(s: &str) -> Vec<u8> {
    let mut v = vec![u8::try_from(s.len()).unwrap()];
    v.extend_from_slice(s.as_bytes());
    v
}
fn str16(s: &str) -> Vec<u8> {
    let mut v = u16::try_from(s.len()).unwrap().to_be_bytes().to_vec();
    v.extend_from_slice(s.as_bytes());
    v
}
fn val(s: &str) -> Vec<u8> {
    str16(s)
}
const ALL: &[u8] = &[0];
fn scope(t: &str) -> Vec<u8> {
    let mut v = vec![1];
    v.extend(str8(t));
    v
}
fn cav(ty: u8, scope: &[u8], params: &[u8]) -> Vec<u8> {
    let mut v = vec![ty];
    v.extend_from_slice(scope);
    v.extend_from_slice(params);
    v
}
fn list8(items: &[&str]) -> Vec<u8> {
    let mut v = vec![u8::try_from(items.len()).unwrap()];
    for i in items {
        v.extend(str8(i));
    }
    v
}
fn tool_allow(tools: &[&str]) -> Vec<u8> {
    cav(1, ALL, &list8(tools))
}
fn arg_eq(sc: &[u8], path: &str, value: &str) -> Vec<u8> {
    cav(2, sc, &[str8(path), val(value)].concat())
}
fn arg_one_of(sc: &[u8], path: &str, values: &[&str]) -> Vec<u8> {
    let mut p = str8(path);
    p.push(u8::try_from(values.len()).unwrap());
    for v in values {
        p.extend(val(v));
    }
    cav(3, sc, &p)
}
fn int_range(sc: &[u8], path: &str, min: i64, max: i64) -> Vec<u8> {
    cav(
        4,
        sc,
        &[
            str8(path),
            min.to_be_bytes().to_vec(),
            max.to_be_bytes().to_vec(),
        ]
        .concat(),
    )
}
fn path_under(path: &str, root: &str) -> Vec<u8> {
    cav(5, ALL, &[str8(path), str16(root)].concat())
}
fn url_origin(path: &str, origins: &[&str]) -> Vec<u8> {
    cav(6, ALL, &[str8(path), list8(origins)].concat())
}
fn email_domain(path: &str, domains: &[&str]) -> Vec<u8> {
    cav(7, ALL, &[str8(path), list8(domains)].concat())
}
fn max_calls(sc: &[u8], n: u32) -> Vec<u8> {
    cav(8, sc, &n.to_be_bytes())
}
fn executor(roles: &[&str]) -> Vec<u8> {
    cav(9, ALL, &list8(roles))
}

fn json_str(s: &str) -> String {
    let mut out = Vec::new();
    // canonical string via the library itself
    out.extend(cjson::canonical(&Value::Str(s.to_string())));
    String::from_utf8(out).unwrap()
}
fn args1(key: &str, value_json: &str) -> Vec<u8> {
    format!("{{\"{key}\":{value_json}}}").into_bytes()
}
fn eval_str(c: &[u8], key: &str, s: &str) -> Option<bool> {
    let a = args1(key, &json_str(s));
    assert!(cjson_valid(&a, true), "test args must be canonical");
    caveat_eval(c, "t", &a)
}

// ------------------------------------------------------------------ matchers

#[test]
fn path_under_bypasses() {
    let c = path_under("/p", "/workspace");
    let ok = [
        "/workspace",
        "/workspace/a.txt",
        "/workspace/d/e/f",
        "/workspace/..a",
    ];
    for v in ok {
        assert_eq!(eval_str(&c, "p", v), Some(true), "{v}");
    }
    let bad = [
        "/workspace/../etc",
        "/workspace/..",
        "/workspace/./a",
        "/workspace-evil",
        "/workspace-evil/x",
        "/workspaces",
        "/workspace/",
        "/workspace//a",
        "//workspace/a",
        "workspace/a",
        "",
        "/",
        "/etc/passwd",
        "/workspace/a\\b",
        "/workspace/a\0b",
        "/Workspace/a",
    ];
    for v in bad {
        assert_eq!(eval_str(&c, "p", v), Some(false), "{v:?}");
    }
    // Non-string and absent values are violations.
    assert_eq!(caveat_eval(&c, "t", b"{\"p\":1}"), Some(false));
    assert_eq!(
        caveat_eval(&c, "t", b"{\"p\":[\"/workspace\"]}"),
        Some(false)
    );
    assert_eq!(caveat_eval(&c, "t", b"{\"q\":\"/workspace\"}"), Some(false));
    // Root "/" admits every valid absolute path.
    let r = path_under("/p", "/");
    assert_eq!(eval_str(&r, "p", "/"), Some(true));
    assert_eq!(eval_str(&r, "p", "/x/y"), Some(true));
    assert_eq!(eval_str(&r, "p", "/x/"), Some(false));
    // Root validity is a decode constraint.
    for root in ["/workspace/", "workspace", "", "/a/../b", "/a//b", "/a\\b"] {
        assert_eq!(
            caveat_eval(&path_under("/p", root), "t", b"{}"),
            None,
            "{root}"
        );
    }
}

#[test]
fn url_origin_bypasses() {
    let c = url_origin("/u", &["https://acme.com:443"]);
    for v in [
        "https://acme.com",
        "https://acme.com/",
        "https://acme.com/x?y#z",
        "https://acme.com:443/x",
        "https://acme.com?q=1",
        "https://acme.com#@evil.com",
    ] {
        assert_eq!(eval_str(&c, "u", v), Some(true), "{v}");
    }
    for v in [
        "https://acme.com.evil.com",
        "https://acme.com.evil.com/",
        "https://evil@acme.com",
        "https://acme.com@evil.com",
        "https://user:pw@acme.com/",
        "https://ACME.com/",
        "https://Acme.Com",
        "HTTPS://acme.com",
        "http://acme.com",
        "https://acme.com:8443/",
        "https://acme.com:0443/",
        "https://acme.com:/",
        "https://acme.com:0/",
        "https://acme.com:443:443/",
        "https://acme.com:99999/",
        "ftp://acme.com",
        "https:/acme.com",
        "https://",
        "https://1.2.3.4/",
        "https://127.0.0.1:443/",
        "https://[::1]/",
        "https://acme.com./",
        "https://-acme.com/",
        "https://acme..com/",
        " https://acme.com",
    ] {
        assert_eq!(eval_str(&c, "u", v), Some(false), "{v}");
    }
    let ip = url_origin("/u", &["http://example.org:80"]);
    assert_eq!(eval_str(&ip, "u", "http://example.org"), Some(true));
    assert_eq!(eval_str(&ip, "u", "http://example.org:80/a"), Some(true));
    assert_eq!(eval_str(&ip, "u", "http://10.0.0.1"), Some(false));
    // Origin form is a decode constraint.
    for o in [
        "https://acme.com",
        "https://acme.com:443/",
        "https://ACME.com:443",
        "https://1.2.3.4:443",
        "https://acme.com:0",
        "https://acme.com:0443",
        "https://acme.com:65536",
        "ftp://acme.com:21",
        "https://u@acme.com:443",
    ] {
        assert_eq!(
            caveat_eval(&url_origin("/u", &[o]), "t", b"{}"),
            None,
            "{o}"
        );
    }
    assert_eq!(
        caveat_eval(&url_origin("/u", &["https://acme.com:65535"]), "t", b"{}"),
        Some(false)
    );
}

#[test]
fn email_domain_bypasses() {
    let c = email_domain("/to", &["acme.com"]);
    for v in [
        "bob@acme.com",
        "bob@ACME.COM",
        "Bob.X+tag@Acme.Com",
        "a@acme.com",
    ] {
        assert_eq!(eval_str(&c, "to", v), Some(true), "{v}");
    }
    for v in [
        "x@acme.com@evil",
        "x@evil@acme.com",
        "@acme.com",
        "acme.com",
        "bob@acme.com.evil.com",
        "bob@evil.com",
        "bob @acme.com",
        "bob@acme.com ",
        "bob@acme.com\n",
        "b\u{f6}b@acme.com",
        "bob@1.2.3.4",
        "bob@",
        "bob@acme.com.",
    ] {
        assert_eq!(eval_str(&c, "to", v), Some(false), "{v:?}");
    }
    assert_eq!(caveat_eval(&c, "t", b"{\"to\":1}"), Some(false));
    assert_eq!(
        caveat_eval(&email_domain("/to", &["ACME.com"]), "t", b"{}"),
        None
    );
    assert_eq!(
        caveat_eval(&email_domain("/to", &["10.0.0.1"]), "t", b"{}"),
        None
    );
}

#[test]
fn int_range_arg_eq_one_of_tool_allow() {
    let r = int_range(ALL, "/amount", 1, 120_000);
    for (a, want) in [
        ("1", true),
        ("120000", true),
        ("0", false),
        ("120001", false),
        ("-1", false),
        ("\"100\"", false),
        ("null", false),
    ] {
        assert_eq!(caveat_eval(&r, "t", &args1("amount", a)), Some(want), "{a}");
    }
    assert_eq!(caveat_eval(&r, "t", b"{}"), Some(false));
    assert_eq!(caveat_eval(&int_range(ALL, "/a", 2, 1), "t", b"{}"), None);
    assert_eq!(
        caveat_eval(
            &int_range(ALL, "/a", i64::MIN, i64::MAX),
            "t",
            b"{\"a\":-9007199254740991}"
        ),
        Some(true)
    );

    let e = arg_eq(ALL, "/to", "\"DE89\"");
    assert_eq!(caveat_eval(&e, "t", b"{\"to\":\"DE89\"}"), Some(true));
    assert_eq!(caveat_eval(&e, "t", b"{\"to\":\"DE890\"}"), Some(false));
    assert_eq!(caveat_eval(&e, "t", b"{\"to\":[\"DE89\"]}"), Some(false));
    let whole = arg_eq(ALL, "", "{\"a\":[1,{\"b\":null}]}");
    assert_eq!(
        caveat_eval(&whole, "t", b"{\"a\":[1,{\"b\":null}]}"),
        Some(true)
    );
    assert_eq!(
        caveat_eval(&whole, "t", b"{\"a\":[1,{\"b\":0}]}"),
        Some(false)
    );
    // Stored values must be canonical cjson (any type, ≤ 1024 bytes).
    assert_eq!(
        caveat_eval(&arg_eq(ALL, "/to", "\"\\u0041\""), "t", b"{}"),
        None
    );
    assert_eq!(caveat_eval(&arg_eq(ALL, "/to", "1.5"), "t", b"{}"), None);
    assert_eq!(caveat_eval(&arg_eq(ALL, "/to", ""), "t", b"{}"), None);
    assert_eq!(caveat_eval(&arg_eq(ALL, "to", "1"), "t", b"{}"), None);
    assert_eq!(caveat_eval(&arg_eq(ALL, "/a~2", "1"), "t", b"{}"), None);
    let big = format!("\"{}\"", "a".repeat(1023));
    assert_eq!(caveat_eval(&arg_eq(ALL, "/a", &big), "t", b"{}"), None);

    let o = arg_one_of(ALL, "/to", &["\"A\"", "\"B\"", "7"]);
    assert_eq!(caveat_eval(&o, "t", b"{\"to\":\"B\"}"), Some(true));
    assert_eq!(caveat_eval(&o, "t", b"{\"to\":7}"), Some(true));
    assert_eq!(caveat_eval(&o, "t", b"{\"to\":\"C\"}"), Some(false));
    assert_eq!(caveat_eval(&arg_one_of(ALL, "/to", &[]), "t", b"{}"), None);

    let t = tool_allow(&["get_balance", "send_money"]);
    assert_eq!(caveat_eval(&t, "send_money", b"{}"), Some(true));
    assert_eq!(caveat_eval(&t, "delete_all", b"{}"), Some(false));
    assert_eq!(caveat_eval(&t, "send_money2", b"{}"), Some(false));
}

#[test]
fn caveat_decode_constraints() {
    // ToolAllow must be scope-all.
    let mut scoped = cav(1, &scope("send_money"), &list8(&["send_money"]));
    assert_eq!(caveat_eval(&scoped, "send_money", b"{}"), None);
    scoped = tool_allow(&["Send"]);
    assert_eq!(caveat_eval(&scoped, "x", b"{}"), None);
    assert_eq!(caveat_eval(&tool_allow(&[]), "x", b"{}"), None);
    let many: Vec<String> = (0..33).map(|i| format!("t{i}")).collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(caveat_eval(&tool_allow(&refs), "t0", b"{}"), None);
    assert_eq!(
        caveat_eval(&tool_allow(&refs[..32]), "t0", b"{}"),
        Some(true)
    );
    // Scope tool name validated; unknown scope tag rejected.
    assert_eq!(
        caveat_eval(&int_range(&scope("Bad"), "/a", 0, 1), "x", b"{}"),
        None
    );
    assert_eq!(caveat_eval(&int_range(&[2], "/a", 0, 1), "x", b"{}"), None);
    // Scope mismatch holds; scope match is evaluated.
    let sc = int_range(&scope("send_money"), "/amount", 1, 10);
    assert_eq!(
        caveat_eval(&sc, "get_balance", b"{\"amount\":99}"),
        Some(true)
    );
    assert_eq!(
        caveat_eval(&sc, "send_money", b"{\"amount\":99}"),
        Some(false)
    );
    // MaxCalls / Executor decode standalone and are not evaluated here.
    assert_eq!(caveat_eval(&max_calls(ALL, 1), "x", b"{}"), Some(true));
    assert_eq!(caveat_eval(&max_calls(ALL, 0), "x", b"{}"), None);
    assert_eq!(caveat_eval(&executor(&["bank"]), "x", b"{}"), Some(true));
    assert_eq!(caveat_eval(&executor(&[""]), "x", b"{}"), None);
    // Unknown type, truncation, trailing bytes.
    assert_eq!(caveat_eval(&cav(0x0A, ALL, &[]), "x", b"{}"), None);
    assert_eq!(caveat_eval(&cav(0, ALL, &[]), "x", b"{}"), None);
    let mut tr = executor(&["bank"]);
    tr.push(0);
    assert_eq!(caveat_eval(&tr, "x", b"{}"), None);
    let full = executor(&["bank"]);
    assert_eq!(caveat_eval(&full[..full.len() - 1], "x", b"{}"), None);
}

// ------------------------------------------------------------------ transcript building

struct Key {
    pk: Vec<u8>,
    sk: ml_dsa_65::PrivateKey,
    id: [u8; 32],
}

fn key(seed: u8) -> Key {
    let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&[seed; 32]);
    let pk = pk.into_bytes().to_vec();
    let id = hd(b"pqsub/v1/agent-id", &pk);
    Key { pk, sk, id }
}

fn sign(k: &Key, msg: &[u8], ctx: &[u8]) -> Vec<u8> {
    k.sk.try_sign_with_seed(&[0u8; 32], msg, ctx)
        .unwrap()
        .to_vec()
}

fn ident(root: &Key, k: &Key, name: &str, role: &str) -> Vec<u8> {
    let mut b = b"PQSI\x01".to_vec();
    b.extend(k.id);
    b.extend(&k.pk);
    b.extend(str8(name));
    b.extend(str8(role));
    b.extend(0u64.to_be_bytes());
    b.extend(10_000_000u64.to_be_bytes());
    b.extend(root.id);
    let s = sign(root, &b, b"pqsub/v1/identity");
    b.extend(s);
    b
}

struct G {
    bytes: Vec<u8>,
    id: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
fn grant_raw(
    issuer: &[u8; 32],
    audience: &[u8; 32],
    parent: &[u8; 32],
    nb: u64,
    na: u64,
    depth: u8,
    caveats: &[Vec<u8>],
    signer: Option<&Key>,
) -> G {
    let mut b = b"PQSG\x01".to_vec();
    b.extend(issuer);
    b.extend(audience);
    b.extend(parent);
    b.extend(nb.to_be_bytes());
    b.extend(na.to_be_bytes());
    b.push(depth);
    b.extend([7u8; 16]);
    b.push(u8::try_from(caveats.len()).unwrap());
    for c in caveats {
        b.extend(c);
    }
    let id = hd(b"pqsub/v2/grant-id", &b);
    let sig = signer.map_or_else(|| vec![0u8; 3309], |k| sign(k, &b, b"pqsub/v2/grant"));
    b.extend(sig);
    G { bytes: b, id }
}

fn grant(issuer: &Key, audience: &[u8; 32], parent: &[u8; 32], depth: u8, cav: &[Vec<u8>]) -> G {
    grant_raw(
        &issuer.id,
        audience,
        parent,
        1000,
        900_000,
        depth,
        cav,
        Some(issuer),
    )
}

enum Rcp<'a> {
    Agent(&'a [u8; 32]),
    Role(&'a str),
}

fn tool_call(tool: &str, args: &[u8], chain: &[[u8; 32]]) -> Vec<u8> {
    let mut v = str8(tool);
    v.extend(u16::try_from(args.len()).unwrap().to_be_bytes());
    v.extend(args);
    v.push(u8::try_from(chain.len()).unwrap());
    for c in chain {
        v.extend(c);
    }
    v
}

fn receipt(call_ref: &[u8; 32], status: u8, reason: u8) -> Vec<u8> {
    let mut v = call_ref.to_vec();
    v.push(status);
    v.push(reason);
    v.extend(if status == 2 { [0u8; 32] } else { [9u8; 32] });
    v
}

#[derive(Default)]
struct Tb {
    ids: Vec<Vec<u8>>,
    grants: Vec<Vec<u8>>,
    entries: Vec<Vec<u8>>,
    hashes: Vec<[u8; 32]>,
    prev: [u8; 32],
    seq: HashMap<[u8; 32], u64>,
}

impl Tb {
    #[allow(clippy::too_many_arguments)]
    fn push_v(
        &mut self,
        version: u8,
        ctx: &[u8],
        k: &Key,
        kind: u8,
        r: &Rcp<'_>,
        ts: u64,
        ext: &[u8],
    ) -> usize {
        let seq = self.seq.entry(k.id).or_insert(0);
        *seq += 1;
        let mut b = b"PQSM".to_vec();
        b.push(version);
        b.push(kind);
        b.extend(k.id);
        match r {
            Rcp::Agent(id) => {
                b.push(1);
                b.extend(*id);
            }
            Rcp::Role(s) => {
                b.push(2);
                b.extend(str8(s));
            }
        }
        b.extend(seq.to_be_bytes());
        b.extend(ts.to_be_bytes());
        b.extend(self.prev);
        b.extend(str16("intent"));
        b.push(0);
        b.extend(ext);
        let h = hd(b"pqsub/v1/entry", &b);
        let s = sign(k, &b, ctx);
        b.extend(s);
        self.entries.push(b);
        self.hashes.push(h);
        self.prev = h;
        self.entries.len() - 1
    }
    fn push(&mut self, k: &Key, kind: u8, r: &Rcp<'_>, ts: u64, ext: &[u8]) -> usize {
        self.push_v(2, b"pqsub/v2/manifest", k, kind, r, ts, ext)
    }
    fn bytes(&self, version: u8) -> Vec<u8> {
        let mut b = b"PQST".to_vec();
        b.push(version);
        let items = |b: &mut Vec<u8>, xs: &[Vec<u8>]| {
            for x in xs {
                b.extend(u32::try_from(x.len()).unwrap().to_be_bytes());
                b.extend(x);
            }
        };
        b.extend(u16::try_from(self.ids.len()).unwrap().to_be_bytes());
        items(&mut b, &self.ids);
        if version == 2 {
            b.extend(u16::try_from(self.grants.len()).unwrap().to_be_bytes());
            items(&mut b, &self.grants);
        }
        b.extend(u32::try_from(self.entries.len()).unwrap().to_be_bytes());
        items(&mut b, &self.entries);
        b
    }
}

struct World {
    root: Key,
    principal: Key,
    agent: Key,
    bank: Key,
    mail: Key,
    g0: G,
    g1: G,
}

fn world() -> World {
    let root = key(1);
    let principal = key(2);
    let agent = key(3);
    let bank = key(4);
    let mail = key(5);
    let g0 = grant(&root, &principal.id, &[0; 32], 3, &[]);
    let g1 = grant(
        &principal,
        &agent.id,
        &g0.id,
        1,
        &[
            tool_allow(&["get_balance", "send_money"]),
            arg_one_of(&scope("send_money"), "/to", &["\"DE89landlord\""]),
            int_range(&scope("send_money"), "/amount", 1, 120_000),
            executor(&["bank"]),
            max_calls(&scope("send_money"), 2),
        ],
    );
    World {
        root,
        principal,
        agent,
        bank,
        mail,
        g0,
        g1,
    }
}

fn base(w: &World) -> Tb {
    let mut t = Tb::default();
    for (k, n, r) in [
        (&w.principal, "principal", "principal"),
        (&w.agent, "agent", "agent"),
        (&w.bank, "bank", "bank"),
        (&w.mail, "mail", "mail"),
    ] {
        t.ids.push(ident(&w.root, k, n, r));
    }
    t.grants.push(w.g0.bytes.clone());
    t.grants.push(w.g1.bytes.clone());
    t
}

const PAY_OK: &[u8] = b"{\"amount\":1000,\"to\":\"DE89landlord\"}";
const PAY_EVIL: &[u8] = b"{\"amount\":5000,\"to\":\"GB-attacker\"}";
const BANK: Rcp<'static> = Rcp::Role("bank");

fn audit(w: &World, t: &Tb) -> Result<Vec<Finding>, &'static str> {
    audit_transcript(&w.root.pk, &t.bytes(2), 0, Anchor::Genesis, None)
        .map(|a| a.findings)
        .map_err(|f| f.code)
}

fn f(code: &'static str, index: usize, call_index: usize, reason: u8, justified: bool) -> Finding {
    Finding {
        code,
        index,
        call_index,
        reason,
        justified,
    }
}

#[test]
fn audit_banking_scenario() {
    let w = world();
    let mut t = base(&w);
    let chain = [w.g0.id, w.g1.id];
    let a = &w.agent;
    let b = &w.bank;
    // 0/1: authorized payment (budget 1/2).
    let c0 = t.push(a, 4, &BANK, 2000, &tool_call("send_money", PAY_OK, &chain));
    t.push(
        b,
        5,
        &Rcp::Agent(&a.id),
        2001,
        &receipt(&t.hashes[c0], 0, 0),
    );
    // 2/3: injected payment refused -> BLOCKED, justified.
    let c2 = t.push(
        a,
        4,
        &BANK,
        2002,
        &tool_call("send_money", PAY_EVIL, &chain),
    );
    t.push(
        b,
        5,
        &Rcp::Agent(&a.id),
        2003,
        &receipt(&t.hashes[c2], 2, 6),
    );
    // 4/5: second authorized payment (budget 2/2), executed with error status.
    let c4 = t.push(a, 4, &BANK, 2004, &tool_call("send_money", PAY_OK, &chain));
    t.push(
        b,
        5,
        &Rcp::Agent(&a.id),
        2005,
        &receipt(&t.hashes[c4], 1, 0),
    );
    // 6/7: third payment executed -> budget exceeded (7).
    let c6 = t.push(a, 4, &BANK, 2006, &tool_call("send_money", PAY_OK, &chain));
    t.push(
        b,
        5,
        &Rcp::Agent(&a.id),
        2007,
        &receipt(&t.hashes[c6], 0, 0),
    );
    // 8/9: harmless call refused -> BLOCKED, not justified (budget scope is send_money only).
    let c8 = t.push(a, 4, &BANK, 2008, &tool_call("get_balance", b"{}", &chain));
    t.push(
        b,
        5,
        &Rcp::Agent(&a.id),
        2009,
        &receipt(&t.hashes[c8], 2, 6),
    );
    // 10: call with no receipt.
    let c10 = t.push(
        a,
        4,
        &BANK,
        2010,
        &tool_call("get_balance", b"{\"x\":1}", &chain),
    );
    // 11/12: injected payment executed -> caveat violation (6).
    let c11 = t.push(
        a,
        4,
        &BANK,
        2011,
        &tool_call("send_money", PAY_EVIL, &chain),
    );
    t.push(
        b,
        5,
        &Rcp::Agent(&a.id),
        2012,
        &receipt(&t.hashes[c11], 0, 0),
    );
    // 13/14: tool outside ToolAllow executed -> 6.
    let c13 = t.push(a, 4, &BANK, 2013, &tool_call("delete_all", b"{}", &chain));
    t.push(
        b,
        5,
        &Rcp::Agent(&a.id),
        2014,
        &receipt(&t.hashes[c13], 0, 0),
    );
    // 15/16: grant expired at executor time (receipt ts after na).
    let c15 = t.push(a, 4, &BANK, 2015, &tool_call("get_balance", b"{}", &chain));
    t.push(
        b,
        5,
        &Rcp::Agent(&a.id),
        900_001,
        &receipt(&t.hashes[c15], 0, 0),
    );

    let rep = verify_transcript(&w.root.pk, &t.bytes(2), 0, Anchor::Genesis, None).unwrap();
    assert_eq!(rep.entry_hashes, t.hashes);
    assert_eq!(
        audit(&w, &t).unwrap(),
        vec![
            f("BLOCKED", 3, 2, 6, true),
            f("EXECUTED_UNAUTHORIZED", 7, 6, 7, false),
            f("BLOCKED", 9, 8, 6, false),
            f("EXECUTED_UNAUTHORIZED", 12, 11, 6, false),
            f("EXECUTED_UNAUTHORIZED", 14, 13, 6, false),
            f("EXECUTED_UNAUTHORIZED", 16, 15, 5, false),
            f("NO_RECEIPT", c10, c10, 0, false),
        ]
    );
    // Window starting at the third call: budget restarts; indices are window-relative.
    let a2 = audit_transcript(&w.root.pk, &t.bytes(2), 6, Anchor::Hash(t.hashes[5]), None).unwrap();
    assert_eq!(a2.findings[0], f("BLOCKED", 3, 2, 6, false));
    assert!(!a2.all_authorized());
}

#[test]
fn audit_grant_failures() {
    let w = world();
    let a = &w.agent;
    let b = &w.bank;
    let run = |chain: &[[u8; 32]], extra: Vec<Vec<u8>>| {
        let mut t = base(&w);
        t.grants.extend(extra);
        let c = t.push(a, 4, &BANK, 2000, &tool_call("get_balance", b"{}", chain));
        t.push(b, 5, &Rcp::Agent(&a.id), 2001, &receipt(&t.hashes[c], 0, 0));
        audit(&w, &t)
    };
    let unauth = |r| Ok(vec![f("EXECUTED_UNAUTHORIZED", 1, 0, r, false)]);
    assert_eq!(run(&[w.g0.id, w.g1.id], vec![]), Ok(vec![]));
    // 2: unknown grant id.
    assert_eq!(run(&[w.g0.id, [5; 32]], vec![]), unauth(2));
    // 3: bad signature (zero sig) and unknown issuer.
    let bad = grant_raw(
        &w.principal.id,
        &a.id,
        &w.g0.id,
        1000,
        900_000,
        1,
        &[],
        None,
    );
    assert_eq!(run(&[w.g0.id, bad.id], vec![bad.bytes]), unauth(3));
    let stranger = key(9);
    let s = grant(&stranger, &a.id, &w.g0.id, 1, &[]);
    assert_eq!(run(&[w.g0.id, s.id], vec![s.bytes]), unauth(3));
    // 3 before 4: bad signature on a grant whose chain is also wrong.
    let bad2 = grant_raw(
        &w.principal.id,
        &a.id,
        &[1; 32],
        1000,
        900_000,
        1,
        &[],
        None,
    );
    assert_eq!(run(&[w.g0.id, bad2.id], vec![bad2.bytes]), unauth(3));
    // 4: chain not rooted / wrong parent / depth not decreasing / wrong leaf audience.
    assert_eq!(run(&[w.g1.id], vec![]), unauth(4));
    let wp = grant(&w.principal, &a.id, &[1; 32], 1, &[]);
    assert_eq!(run(&[w.g0.id, wp.id], vec![wp.bytes]), unauth(4));
    let wd = grant(&w.principal, &a.id, &w.g0.id, 3, &[]);
    assert_eq!(run(&[w.g0.id, wd.id], vec![wd.bytes]), unauth(4));
    let wa = grant(&w.principal, &w.mail.id, &w.g0.id, 1, &[]);
    assert_eq!(run(&[w.g0.id, wa.id], vec![wa.bytes]), unauth(4));
    let wi = grant(&w.mail, &a.id, &w.g0.id, 1, &[]);
    assert_eq!(run(&[w.g0.id, wi.id], vec![wi.bytes]), unauth(4));
    // Executor caveat vs Agent(id) recipient on the call -> 6.
    let mut t = base(&w);
    let c = t.push(
        a,
        4,
        &Rcp::Agent(&b.id),
        2000,
        &tool_call("get_balance", b"{}", &[w.g0.id, w.g1.id]),
    );
    t.push(b, 5, &Rcp::Agent(&a.id), 2001, &receipt(&t.hashes[c], 0, 0));
    assert_eq!(audit(&w, &t), unauth(6));
}

#[test]
fn audit_fatal_errors() {
    let w = world();
    let a = &w.agent;
    let b = &w.bank;
    let chain = [w.g0.id, w.g1.id];
    // Orphan: unknown call_ref.
    let mut t = base(&w);
    t.push(a, 4, &BANK, 2000, &tool_call("get_balance", b"{}", &chain));
    t.push(b, 5, &Rcp::Agent(&a.id), 2001, &receipt(&[3; 32], 0, 0));
    assert_eq!(audit(&w, &t), Err("RECEIPT_ORPHAN"));
    // Orphan: referencing a non-call entry.
    let mut t = base(&w);
    let h = t.push(a, 1, &BANK, 2000, &[]);
    t.push(b, 5, &Rcp::Agent(&a.id), 2001, &receipt(&t.hashes[h], 0, 0));
    assert_eq!(audit(&w, &t), Err("RECEIPT_ORPHAN"));
    // Orphan: call before the window.
    let mut t = base(&w);
    let c = t.push(a, 4, &BANK, 2000, &tool_call("get_balance", b"{}", &chain));
    t.push(b, 5, &Rcp::Agent(&a.id), 2001, &receipt(&t.hashes[c], 0, 0));
    let r = audit_transcript(&w.root.pk, &t.bytes(2), 1, Anchor::None, None);
    assert_eq!(r.map(|_| ()).map_err(|f| f.code), Err("RECEIPT_ORPHAN"));
    // Duplicate receipt.
    let mut t = base(&w);
    let c = t.push(a, 4, &BANK, 2000, &tool_call("get_balance", b"{}", &chain));
    t.push(b, 5, &Rcp::Agent(&a.id), 2001, &receipt(&t.hashes[c], 0, 0));
    t.push(b, 5, &Rcp::Agent(&a.id), 2002, &receipt(&t.hashes[c], 2, 6));
    assert_eq!(audit(&w, &t), Err("DUPLICATE_RECEIPT"));
    // Wrong executor: role mismatch, and agent-id mismatch.
    let mut t = base(&w);
    let c = t.push(a, 4, &BANK, 2000, &tool_call("get_balance", b"{}", &chain));
    t.push(
        &w.mail,
        5,
        &Rcp::Agent(&a.id),
        2001,
        &receipt(&t.hashes[c], 0, 0),
    );
    assert_eq!(audit(&w, &t), Err("RECEIPT_WRONG_EXECUTOR"));
    let mut t = base(&w);
    let c = t.push(
        a,
        4,
        &Rcp::Agent(&b.id),
        2000,
        &tool_call("get_balance", b"{}", &chain),
    );
    t.push(
        &w.mail,
        5,
        &Rcp::Agent(&a.id),
        2001,
        &receipt(&t.hashes[c], 2, 4),
    );
    assert_eq!(audit(&w, &t), Err("RECEIPT_WRONG_EXECUTOR"));
    // v1 failures are reported first and with v1 codes.
    let mut t = base(&w);
    t.push_v(2, b"pqsub/v1/manifest", a, 1, &BANK, 2000, &[]);
    assert_eq!(audit(&w, &t), Err("BAD_SIGNATURE"));
    let mut t = base(&w);
    t.push(b, 5, &Rcp::Agent(&a.id), 2001, &receipt(&[3; 32], 0, 0));
    t.push(a, 1, &BANK, 99_999_999, &[]);
    assert_eq!(audit(&w, &t), Err("IDENTITY_EXPIRED"));
}

#[test]
fn v1_manifests_in_v2_and_v1_transcripts() {
    let w = world();
    let a = &w.agent;
    // v1 manifest inside a v2 transcript (with grants) verifies with the v1 ctx.
    let mut t = base(&w);
    t.push_v(1, b"pqsub/v1/manifest", a, 1, &BANK, 2000, &[]);
    t.push(a, 1, &BANK, 2001, &[]);
    assert!(verify_transcript(&w.root.pk, &t.bytes(2), 0, Anchor::Genesis, None).is_ok());
    assert_eq!(audit(&w, &t), Ok(vec![]));
    // The v1 container rejects the v2 manifest...
    let code = |b: &[u8]| {
        verify_transcript(&w.root.pk, b, 0, Anchor::Genesis, None)
            .map(|_| ())
            .map_err(|f| f.code)
    };
    assert_eq!(code(&t.bytes(1)), Err("DECODE"));
    // ...but accepts v1-only content, which a v2 container without grants must not carry.
    let mut t = base(&w);
    t.grants.clear();
    t.push_v(1, b"pqsub/v1/manifest", a, 1, &BANK, 2000, &[]);
    assert_eq!(code(&t.bytes(1)), Ok(()));
    assert_eq!(code(&t.bytes(2)), Err("DECODE"));
    // v1 manifest with kind 4 is a decode error.
    let mut t = base(&w);
    t.push_v(
        1,
        b"pqsub/v1/manifest",
        a,
        4,
        &BANK,
        2000,
        &tool_call("x", b"{}", &[w.g0.id]),
    );
    assert_eq!(code(&t.bytes(2)), Err("DECODE"));
}

/// Decode-only transcript checks: no real signatures needed.
#[test]
fn transcript_v2_decode_rules() {
    let root = vec![0u8; 1952];
    let z = [0u8; 32];
    let tx = |grants: &[Vec<u8>]| {
        let t = Tb {
            grants: grants.to_vec(),
            ..Tb::default()
        };
        verify_transcript(&root, &t.bytes(2), 0, Anchor::Genesis, None)
            .map(|_| ())
            .map_err(|f| f.code)
    };
    let g = |c: &[Vec<u8>]| grant_raw(&z, &z, &z, 1, 2, 0, c, None).bytes;
    assert_eq!(tx(&[]), Err("DECODE"));
    assert_eq!(tx(&[g(&[])]), Ok(()));
    // MaxCalls requires an Executor caveat in the same grant.
    assert_eq!(tx(&[g(&[max_calls(ALL, 3)])]), Err("DECODE"));
    assert_eq!(tx(&[g(&[max_calls(ALL, 3), executor(&["bank"])])]), Ok(()));
    assert_eq!(
        tx(&[g(&[executor(&["bank"]), max_calls(&scope("x"), 1)])]),
        Ok(())
    );
    // Duplicate grant ids (same body) are rejected.
    assert_eq!(tx(&[g(&[]), g(&[])]), Err("DECODE"));
    // nb > na, too many caveats, invalid caveat inside a grant.
    assert_eq!(
        tx(&[grant_raw(&z, &z, &z, 3, 2, 0, &[], None).bytes]),
        Err("DECODE")
    );
    let many: Vec<Vec<u8>> = (0..33).map(|_| executor(&["r"])).collect();
    assert_eq!(tx(&[g(&many)]), Err("DECODE"));
    assert_eq!(tx(&[g(&many[..32])]), Ok(()));
    assert_eq!(tx(&[g(&[tool_allow(&["UPPER"])])]), Err("DECODE"));
    // Trailing bytes after the signature.
    let mut tb = g(&[]);
    tb.push(0);
    assert_eq!(tx(&[tb]), Err("DECODE"));
}

#[test]
fn manifest_v2_decode_rules() {
    let w = world();
    let a = &w.agent;
    let code = |t: &Tb| {
        verify_transcript(&w.root.pk, &t.bytes(2), 0, Anchor::Genesis, None)
            .map(|_| ())
            .map_err(|f| f.code)
    };
    let one = |kind: u8, ext: Vec<u8>| {
        let mut t = base(&w);
        t.push(a, kind, &BANK, 2000, &ext);
        code(&t)
    };
    let ch = [w.g0.id];
    assert_eq!(one(4, tool_call("send_money", b"{}", &ch)), Ok(()));
    assert_eq!(one(4, tool_call("Send", b"{}", &ch)), Err("DECODE"));
    assert_eq!(one(4, tool_call("", b"{}", &ch)), Err("DECODE"));
    assert_eq!(one(4, tool_call("x", b"[]", &ch)), Err("DECODE"));
    assert_eq!(one(4, tool_call("x", b"{ }", &ch)), Err("DECODE"));
    assert_eq!(one(4, tool_call("x", b"{}", &[])), Err("DECODE"));
    assert_eq!(one(4, tool_call("x", b"{}", &[[0; 32]; 9])), Err("DECODE"));
    assert_eq!(one(4, tool_call("x", b"{}", &[[0; 32]; 8])), Ok(()));
    // Kind 6 (§14.13): ext is exactly target[32].
    assert_eq!(one(6, vec![]), Err("DECODE"));
    assert_eq!(one(6, vec![7; 31]), Err("DECODE"));
    assert_eq!(one(6, vec![7; 33]), Err("DECODE"));
    assert_eq!(one(6, vec![7; 32]), Ok(()));
    assert_eq!(one(7, vec![7; 32]), Err("DECODE"));
    assert_eq!(one(5, receipt(&[0; 32], 3, 0)), Err("DECODE"));
    assert_eq!(one(5, receipt(&[0; 32], 0, 2)), Err("DECODE"));
    assert_eq!(one(5, receipt(&[0; 32], 2, 1)), Err("DECODE"));
    // §14.13 item 2: reason 9 GRANT_REVOKED is valid for status 2; 10 is not.
    assert_eq!(one(5, receipt(&[0; 32], 2, 9)), Ok(()));
    assert_eq!(one(5, receipt(&[0; 32], 2, 10)), Err("DECODE"));
    assert_eq!(one(5, receipt(&[0; 32], 0, 9)), Err("DECODE"));
    let mut nz = receipt(&[0; 32], 2, 6);
    nz[40] = 1;
    assert_eq!(one(5, nz), Err("DECODE"));
    // A well-formed receipt passes v1 verification (audit then flags it as an orphan).
    assert_eq!(one(5, receipt(&[0; 32], 2, 8)), Ok(()));
}

// ------------------------------------------------------------------ revocation (§14.13)

const ANY: Rcp<'static> = Rcp::Role("*");

fn revocation(target: &[u8; 32]) -> Vec<u8> {
    target.to_vec()
}

#[test]
fn revocation_kind6_only_in_v2_manifests() {
    let w = world();
    let mut t = base(&w);
    t.push_v(
        1,
        b"pqsub/v1/manifest",
        &w.principal,
        6,
        &ANY,
        2000,
        &revocation(&w.g1.id),
    );
    let r = verify_transcript(&w.root.pk, &t.bytes(2), 0, Anchor::Genesis, None);
    assert_eq!(r.map(|_| ()).map_err(|f| f.code), Err("DECODE"));
    // Any recipient is accepted; a v2 container holding only a kind-6 v2 manifest
    // (no grants) is canonical.
    let mut t = base(&w);
    t.grants.clear();
    t.push(
        &w.principal,
        6,
        &Rcp::Agent(&w.bank.id),
        2000,
        &revocation(&w.g1.id),
    );
    assert_eq!(audit(&w, &t), Ok(vec![]));
}

#[test]
fn revocation_is_positional() {
    let w = world();
    let (a, b, p) = (&w.agent, &w.bank, &w.principal);
    let chain = [w.g0.id, w.g1.id];
    let call =
        |t: &mut Tb, ts: u64| t.push(a, 4, &BANK, ts, &tool_call("get_balance", b"{}", &chain));
    let rcpt = |t: &mut Tb, c: usize, ts: u64, status: u8, reason: u8| {
        let h = t.hashes[c];
        t.push(b, 5, &Rcp::Agent(&a.id), ts, &receipt(&h, status, reason))
    };

    let mut t = base(&w);
    // 0/1: executed before the revocation: stays authorized (no backdating).
    let c0 = call(&mut t, 2000);
    rcpt(&mut t, c0, 2001, 0, 0);
    // 2/3: refused with reason 9 before any revocation exists: not justified.
    let c2 = call(&mut t, 2002);
    rcpt(&mut t, c2, 2003, 2, 9);
    // 4: call; 5: revocation lands between the call and its receipt; 6: receipt.
    let c4 = call(&mut t, 2004);
    // The revocation's own timestamp is irrelevant (an early ts cannot backdate).
    let rev = t.push(p, 6, &ANY, 1, &revocation(&w.g1.id));
    rcpt(&mut t, c4, 2006, 0, 0);
    // 7/8: executed after the revocation.
    let c7 = call(&mut t, 2007);
    rcpt(&mut t, c7, 2008, 1, 0);
    // 9/10: refused after the revocation: justified.
    let c9 = call(&mut t, 2009);
    rcpt(&mut t, c9, 2010, 2, 9);
    assert_eq!(rev, 5);
    assert_eq!(
        audit(&w, &t).unwrap(),
        vec![
            f("BLOCKED", 3, 2, 9, false),
            f("EXECUTED_UNAUTHORIZED", 6, 4, 9, false),
            f("EXECUTED_UNAUTHORIZED", 8, 7, 9, false),
            f("BLOCKED", 10, 9, 9, true),
        ]
    );
    // A window starting after the revocation does not know it (item 7).
    let a2 = audit_transcript(&w.root.pk, &t.bytes(2), 7, Anchor::Hash(t.hashes[6]), None).unwrap();
    assert_eq!(a2.findings, vec![f("BLOCKED", 3, 2, 9, false)]);
    assert!(a2.all_authorized());
    // A window starting at call 4 contains the revocation and applies it.
    let a3 = audit_transcript(&w.root.pk, &t.bytes(2), 4, Anchor::Hash(t.hashes[3]), None).unwrap();
    assert_eq!(
        a3.findings,
        vec![
            f("EXECUTED_UNAUTHORIZED", 2, 0, 9, false),
            f("EXECUTED_UNAUTHORIZED", 4, 3, 9, false),
            f("BLOCKED", 6, 5, 9, true),
        ]
    );

    // A receipt pointing at a kind-6 entry is an orphan.
    let mut t = base(&w);
    let r = t.push(p, 6, &ANY, 2000, &revocation(&w.g1.id));
    let h = t.hashes[r];
    t.push(b, 5, &Rcp::Agent(&a.id), 2001, &receipt(&h, 0, 0));
    assert_eq!(audit(&w, &t), Err("RECEIPT_ORPHAN"));
}

/// Three-grant chain root -> principal -> agent -> mail (`g2` issued by agent).
fn sub_grant(w: &World) -> G {
    grant(&w.agent, &w.mail.id, &w.g1.id, 0, &[])
}

#[test]
fn revocation_entitlement() {
    let w = world();
    let g2 = sub_grant(&w);
    let other = grant(&w.principal, &w.bank.id, &w.g0.id, 1, &[]);
    let chain = [w.g0.id, w.g1.id, g2.id];
    // Revocations (revoker, target) followed by one executed call by `mail` via chain.
    let run = |revs: &[(&Key, [u8; 32])]| {
        let mut t = base(&w);
        t.grants.push(g2.bytes.clone());
        t.grants.push(other.bytes.clone());
        for (k, target) in revs {
            t.push(k, 6, &ANY, 1500, &revocation(target));
        }
        let c = t.push(
            &w.mail,
            4,
            &BANK,
            2000,
            &tool_call("get_balance", b"{}", &chain),
        );
        let h = t.hashes[c];
        t.push(
            &w.bank,
            5,
            &Rcp::Agent(&w.mail.id),
            2001,
            &receipt(&h, 0, 0),
        );
        audit(&w, &t).map(|v| v.iter().map(|f| f.reason).collect::<Vec<_>>())
    };
    let revoked = Ok(vec![9]);
    let fine = Ok(vec![]);
    assert_eq!(run(&[]), fine);
    // Issuer of the grant itself.
    assert_eq!(run(&[(&w.principal, w.g1.id)]), revoked);
    assert_eq!(run(&[(&w.agent, g2.id)]), revoked);
    // Issuer of an ancestor in this chain.
    assert_eq!(run(&[(&w.principal, g2.id)]), revoked);
    // A descendant cannot revoke an ancestor; no transcript identity can revoke g0.
    assert_eq!(run(&[(&w.agent, w.g1.id)]), fine);
    assert_eq!(run(&[(&w.principal, w.g0.id)]), fine);
    assert_eq!(run(&[(&w.agent, w.g0.id)]), fine);
    // The audience of a grant is not its issuer.
    assert_eq!(run(&[(&w.mail, g2.id)]), fine);
    // Strangers, unknown targets, and grants outside the chain have no effect.
    assert_eq!(run(&[(&w.bank, w.g1.id)]), fine);
    assert_eq!(run(&[(&w.principal, [5; 32])]), fine);
    assert_eq!(run(&[(&w.principal, other.id)]), fine);
    // Duplicates are harmless.
    assert_eq!(
        run(&[(&w.agent, g2.id), (&w.agent, g2.id), (&w.bank, g2.id)]),
        revoked
    );
}

#[test]
fn revocation_check_order_and_budget() {
    let w = world();
    let g2 = sub_grant(&w);
    let (a, b, m, p) = (&w.agent, &w.bank, &w.mail, &w.principal);
    let short = [w.g0.id, w.g1.id];
    let long = [w.g0.id, w.g1.id, g2.id];
    let mut t = base(&w);
    t.grants.push(g2.bytes.clone());
    t.push(p, 6, &ANY, 1500, &revocation(&g2.id));
    let exec = |t: &mut Tb, k: &Key, chain: &[[u8; 32]], args: &[u8], rts: u64| {
        let ts = 2000 + t.entries.len() as u64;
        let c = t.push(k, 4, &BANK, ts, &tool_call("send_money", args, chain));
        let h = t.hashes[c];
        t.push(b, 5, &Rcp::Agent(&k.id), rts, &receipt(&h, 0, 0));
    };
    // 1/2: revoked + expired at executor time -> 5 (steps 1-4 first).
    exec(&mut t, m, &long, PAY_OK, 900_001);
    // 3/4: revoked + caveat violation -> 9 (4a precedes 5).
    exec(&mut t, m, &long, PAY_EVIL, 3000);
    // 5/6: revoked + unknown grant later in the chain -> 2.
    exec(&mut t, m, &[w.g0.id, w.g1.id, g2.id, [5; 32]], PAY_OK, 3000);
    // 7/8, 9/10: refused via g2 never consumes the shared g1 budget (MaxCalls 2).
    exec(&mut t, m, &long, PAY_OK, 3000);
    exec(&mut t, m, &long, PAY_OK, 3000);
    // 11..=16: the unrevoked chain [g0, g1] still has its full budget of 2.
    exec(&mut t, a, &short, PAY_OK, 3000);
    exec(&mut t, a, &short, PAY_OK, 3000);
    exec(&mut t, a, &short, PAY_OK, 3000);
    assert_eq!(
        audit(&w, &t).unwrap(),
        vec![
            f("EXECUTED_UNAUTHORIZED", 2, 1, 5, false),
            f("EXECUTED_UNAUTHORIZED", 4, 3, 9, false),
            f("EXECUTED_UNAUTHORIZED", 6, 5, 2, false),
            f("EXECUTED_UNAUTHORIZED", 8, 7, 9, false),
            f("EXECUTED_UNAUTHORIZED", 10, 9, 9, false),
            f("EXECUTED_UNAUTHORIZED", 16, 15, 7, false),
        ]
    );
}

// ------------------------------------------------------------------ vectors_v2 runner

#[test]
fn vectors_v2_runner_cases() {
    use serde_json::json;
    let w = world();
    let a = &w.agent;
    let b = &w.bank;
    let chain = [w.g0.id, w.g1.id];
    let mut t = base(&w);
    let c0 = t.push(a, 4, &BANK, 2000, &tool_call("send_money", PAY_OK, &chain));
    t.push(
        b,
        5,
        &Rcp::Agent(&a.id),
        2001,
        &receipt(&t.hashes[c0], 0, 0),
    );
    let c2 = t.push(
        a,
        4,
        &BANK,
        2002,
        &tool_call("send_money", PAY_EVIL, &chain),
    );
    t.push(
        b,
        5,
        &Rcp::Agent(&a.id),
        2003,
        &receipt(&t.hashes[c2], 2, 6),
    );
    t.push(a, 4, &BANK, 2004, &tool_call("get_balance", b"{}", &chain));
    let tr = hex::encode(t.bytes(2));
    let hx: Vec<String> = t.hashes.iter().map(hex::encode).collect();
    let ids = [&a.id, &b.id, &a.id, &b.id, &a.id].map(hex::encode);
    let mut orphan = base(&w);
    orphan.push(b, 5, &Rcp::Agent(&a.id), 2001, &receipt(&[3; 32], 0, 0));
    let mk = |blocked_reason: u8| {
        json!({
            "format": "pqsub-test-vectors/v2",
            "root_pk": hex::encode(&w.root.pk),
            "cjson": [
                {"name": "empty", "input": hex::encode(b"{}"), "object": true, "valid": true},
                {"name": "ws", "input": hex::encode(b"{ }"), "object": true, "valid": false}
            ],
            "caveats": [
                {"name": "range", "caveat": hex::encode(int_range(ALL, "/n", 1, 2)),
                 "decode_ok": true, "tool": "x", "args": hex::encode(b"{\"n\":3}"), "holds": false},
                {"name": "bad", "caveat": hex::encode(max_calls(ALL, 0)),
                 "decode_ok": false, "tool": null, "args": null, "holds": null}
            ],
            "cases": [
                {"name": "full", "description": "d", "transcript": tr, "from": 0, "anchor": "genesis",
                 "expect": {"ok": true, "head": hx[4], "entry_hashes": hx, "agent_ids": ids,
                    "findings": [
                        {"code": "BLOCKED", "index": 3, "call_index": 2, "reason": blocked_reason, "justified": true},
                        {"code": "NO_RECEIPT", "index": 4, "call_index": 4, "reason": 0}
                    ]}},
                {"name": "window", "transcript": tr, "from": 4, "anchor": hx[3], "expected_head": hx[4],
                 "expect": {"ok": true, "head": hx[4], "entry_hashes": [hx[4]], "agent_ids": [ids[4]],
                    "findings": [{"code": "NO_RECEIPT", "index": 0, "call_index": 0, "reason": 0}]}},
                {"name": "orphan", "transcript": hex::encode(orphan.bytes(2)), "from": 0, "anchor": "genesis",
                 "expect": {"ok": false, "error": "RECEIPT_ORPHAN"}},
                {"name": "head", "transcript": tr, "from": 0, "anchor": "none", "expected_head": hx[0],
                 "expect": {"ok": false, "error": "HEAD_MISMATCH"}}
            ]
        })
        .to_string()
    };
    let s = pqsub_verify::vectors_v2::run(&mk(6)).unwrap();
    assert!(s.failures.is_empty(), "{:?}", s.failures);
    assert_eq!(s.passed, 2 + 2 + 2 * 2 + 2);
    let s = pqsub_verify::vectors_v2::run(&mk(5)).unwrap();
    assert_eq!(s.failures.len(), 1, "{:?}", s.failures);
}
