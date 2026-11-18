//! Caveat encoding (V2_DESIGN §14.3) and matchers (§14.4).

use crate::cjson::{self, Value};
use crate::{fail, Cur, Failure, Recipient};

const MAX_TOOL: usize = 64;
const MAX_ROLE: usize = 64;
const MAX_LIST: u8 = 32;

/// Which tool calls a caveat applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// All tools.
    All,
    /// Only calls to this tool.
    Tool(String),
}

/// Caveat type and parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// 0x01: `call.tool` is in the set.
    ToolAllow(Vec<String>),
    /// 0x02: value at path is byte-equal to the canonical value.
    ArgEq {
        /// JSON pointer.
        path: String,
        /// Canonical value bytes.
        value: Vec<u8>,
    },
    /// 0x03: value at path is byte-equal to one of the canonical values.
    ArgOneOf {
        /// JSON pointer.
        path: String,
        /// Canonical value bytes.
        values: Vec<Vec<u8>>,
    },
    /// 0x04: value at path is an integer in `min..=max`.
    IntRange {
        /// JSON pointer.
        path: String,
        /// Inclusive minimum.
        min: i64,
        /// Inclusive maximum.
        max: i64,
    },
    /// 0x05: value at path is an absolute path under `root`.
    PathUnder {
        /// JSON pointer.
        path: String,
        /// Root path (validated absolute path).
        root: String,
    },
    /// 0x06: value at path is a URL whose origin is listed.
    UrlOrigin {
        /// JSON pointer.
        path: String,
        /// `scheme://host:port` origins.
        origins: Vec<String>,
    },
    /// 0x07: value at path is an email address whose domain is listed.
    EmailDomain {
        /// JSON pointer.
        path: String,
        /// Lowercase hosts.
        domains: Vec<String>,
    },
    /// 0x08: per-grant execution budget (evaluated in the budget step).
    MaxCalls(u32),
    /// 0x09: executor role restriction.
    Executor(Vec<String>),
}

/// A decoded caveat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caveat {
    /// Scope.
    pub scope: Scope,
    /// Type and parameters.
    pub kind: Kind,
}

// ------------------------------------------------------------------ syntax helpers

/// Tool name: 1..=64 bytes of `[a-z0-9_.-]`.
#[must_use]
pub fn valid_tool(s: &str) -> bool {
    (1..=MAX_TOOL).contains(&s.len())
        && s.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'))
}

pub(crate) fn tool_name(c: &mut Cur<'_>) -> Result<String, Failure> {
    let t = c.str_range(1, 0, 255)?;
    if !valid_tool(&t) {
        return fail("DECODE", "tool name");
    }
    Ok(t)
}

/// Host (§14.4): lowercase DNS labels, last label not all digits, ≤ 253 bytes.
#[must_use]
pub fn valid_host(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let labels_ok = s.split('.').all(|l| {
        let b = l.as_bytes();
        (1..=63).contains(&b.len())
            && b.iter()
                .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-'))
            && b.first() != Some(&b'-')
            && b.last() != Some(&b'-')
    });
    let last_ok = s
        .rsplit('.')
        .next()
        .is_some_and(|l| !l.bytes().all(|c| c.is_ascii_digit()));
    labels_ok && last_ok
}

/// Segments of a valid absolute path (§14.4), or `None` if invalid.
#[must_use]
pub fn abs_path_segments(s: &str) -> Option<Vec<&str>> {
    let rest = s.strip_prefix('/')?;
    if s.contains('\\') || s.contains('\0') {
        return None;
    }
    if rest.is_empty() {
        return Some(Vec::new());
    }
    let segs: Vec<&str> = rest.split('/').collect();
    if segs.iter().any(|g| g.is_empty() || *g == "." || *g == "..") {
        return None;
    }
    Some(segs)
}

/// Port: 1..=5 digits, no leading zero, in 1..=65535.
fn valid_port(p: &str) -> Option<u16> {
    let b = p.as_bytes();
    if b.is_empty() || b.len() > 5 || !b.iter().all(u8::is_ascii_digit) || b.first() == Some(&b'0')
    {
        return None;
    }
    p.parse::<u16>().ok().filter(|&n| n >= 1)
}

fn split_scheme(s: &str) -> Option<(&'static str, &str, u16)> {
    if let Some(r) = s.strip_prefix("https://") {
        Some(("https", r, 443))
    } else {
        s.strip_prefix("http://").map(|r| ("http", r, 80))
    }
}

/// Origin `scheme://host:port` of a URL value (§14.4), or `None` if it does not parse.
#[must_use]
pub fn url_origin(s: &str) -> Option<String> {
    let (scheme, rest, default_port) = split_scheme(s)?;
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let auth = rest.get(..auth_end)?;
    if auth.contains('@') {
        return None;
    }
    let (host, port) = match auth.split_once(':') {
        Some((h, p)) => (h, valid_port(p)?),
        None => (auth, default_port),
    };
    if !valid_host(host) {
        return None;
    }
    Some(format!("{scheme}://{host}:{port}"))
}

/// Exact listed-origin form `scheme://host:port` with an explicit port (§14.3).
#[must_use]
pub fn valid_origin(s: &str) -> bool {
    let Some((_, rest, _)) = split_scheme(s) else {
        return false;
    };
    let Some((host, port)) = rest.split_once(':') else {
        return false;
    };
    valid_host(host) && valid_port(port).is_some()
}

/// Lowercased domain of an email value (§14.4), or `None` if invalid.
#[must_use]
pub fn email_domain(s: &str) -> Option<String> {
    if !s.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return None;
    }
    let (local, domain) = s.split_once('@')?;
    if local.is_empty() || domain.contains('@') {
        return None;
    }
    let d = domain.to_ascii_lowercase();
    valid_host(&d).then_some(d)
}

// ------------------------------------------------------------------ decoding

fn path(c: &mut Cur<'_>) -> Result<String, Failure> {
    let p = c.str_range(1, 0, 255)?;
    if !cjson::valid_pointer(&p) {
        return fail("DECODE", "json pointer");
    }
    Ok(p)
}

fn count(c: &mut Cur<'_>) -> Result<u8, Failure> {
    let n = c.u8()?;
    if !(1..=MAX_LIST).contains(&n) {
        return fail("DECODE", "list length");
    }
    Ok(n)
}

fn value(c: &mut Cur<'_>) -> Result<Vec<u8>, Failure> {
    let n = c.be(2)? as usize;
    let raw = c.take(n)?;
    if !cjson::cjson_valid(raw, false) {
        return fail("DECODE", "caveat value is not canonical JSON");
    }
    Ok(raw.to_vec())
}

fn list<T>(
    c: &mut Cur<'_>,
    mut one: impl FnMut(&mut Cur<'_>) -> Result<T, Failure>,
) -> Result<Vec<T>, Failure> {
    let n = count(c)?;
    let mut v = Vec::with_capacity(usize::from(n));
    for _ in 0..n {
        v.push(one(c)?);
    }
    Ok(v)
}

/// Decode one caveat from the cursor (§14.3).
pub(crate) fn decode(c: &mut Cur<'_>) -> Result<Caveat, Failure> {
    let ty = c.u8()?;
    let scope = match c.u8()? {
        0 => Scope::All,
        1 => Scope::Tool(tool_name(c)?),
        _ => return fail("DECODE", "caveat scope"),
    };
    let kind = match ty {
        1 => {
            if scope != Scope::All {
                return fail("DECODE", "ToolAllow must have scope all");
            }
            Kind::ToolAllow(list(c, tool_name)?)
        }
        2 => {
            let path = path(c)?;
            Kind::ArgEq {
                path,
                value: value(c)?,
            }
        }
        3 => {
            let path = path(c)?;
            Kind::ArgOneOf {
                path,
                values: list(c, value)?,
            }
        }
        4 => {
            let path = path(c)?;
            let min = c.be(8)? as i64;
            let max = c.be(8)? as i64;
            if min > max {
                return fail("DECODE", "IntRange min > max");
            }
            Kind::IntRange { path, min, max }
        }
        5 => {
            let path = path(c)?;
            let root = c.str_range(2, 0, usize::from(u16::MAX))?;
            if abs_path_segments(&root).is_none() {
                return fail("DECODE", "PathUnder root");
            }
            Kind::PathUnder { path, root }
        }
        6 => {
            let path = path(c)?;
            let origins = list(c, |c| {
                let o = c.str_range(1, 0, 255)?;
                if !valid_origin(&o) {
                    return fail("DECODE", "origin");
                }
                Ok(o)
            })?;
            Kind::UrlOrigin { path, origins }
        }
        7 => {
            let path = path(c)?;
            let domains = list(c, |c| {
                let d = c.str_range(1, 0, 255)?;
                if !valid_host(&d) {
                    return fail("DECODE", "domain");
                }
                Ok(d)
            })?;
            Kind::EmailDomain { path, domains }
        }
        8 => {
            let n = c.be(4)?;
            let n = u32::try_from(n).unwrap_or(0);
            if n == 0 {
                return fail("DECODE", "MaxCalls must be >= 1");
            }
            Kind::MaxCalls(n)
        }
        9 => Kind::Executor(list(c, |c| c.text(1, MAX_ROLE))?),
        _ => return fail("DECODE", "caveat type"),
    };
    Ok(Caveat { scope, kind })
}

/// Decode a standalone caveat; the bytes must be consumed exactly.
#[must_use]
pub fn decode_one(bytes: &[u8]) -> Option<Caveat> {
    let mut c = Cur::new(bytes);
    let cv = decode(&mut c).ok()?;
    c.end().ok()?;
    Some(cv)
}

// ------------------------------------------------------------------ evaluation

/// Executor context for the `Executor` caveat: the call's recipient and the
/// executor identity's role.
pub(crate) struct ExecCtx<'a> {
    pub(crate) recipient: &'a Recipient,
    pub(crate) executor_role: &'a str,
}

impl Caveat {
    /// Whether this caveat applies to a call of `tool`.
    #[must_use]
    pub fn scope_matches(&self, tool: &str) -> bool {
        match &self.scope {
            Scope::All => true,
            Scope::Tool(t) => t == tool,
        }
    }

    /// Matcher evaluation (§14.4), ignoring scope. `MaxCalls` always holds here
    /// (budget step); `Executor` holds when `exec` is `None` (not evaluated).
    pub(crate) fn holds(
        &self,
        tool: &str,
        args: Option<&Value>,
        exec: Option<&ExecCtx<'_>>,
    ) -> bool {
        let at = |p: &str| args.and_then(|a| cjson::pointer(a, p));
        let string_at = |p: &str| match at(p) {
            Some(Value::Str(s)) => Some(s.as_str()),
            _ => None,
        };
        match &self.kind {
            Kind::ToolAllow(set) => set.iter().any(|t| t == tool),
            Kind::ArgEq { path, value } => at(path).is_some_and(|v| cjson::canonical(v) == *value),
            Kind::ArgOneOf { path, values } => at(path).is_some_and(|v| {
                let c = cjson::canonical(v);
                values.contains(&c)
            }),
            Kind::IntRange { path, min, max } => {
                matches!(at(path), Some(Value::Int(v)) if min <= v && v <= max)
            }
            Kind::PathUnder { path, root } => {
                let (Some(v), Some(r)) = (
                    string_at(path).and_then(abs_path_segments),
                    abs_path_segments(root),
                ) else {
                    return false;
                };
                v.starts_with(&r)
            }
            Kind::UrlOrigin { path, origins } => string_at(path)
                .and_then(url_origin)
                .is_some_and(|o| origins.contains(&o)),
            Kind::EmailDomain { path, domains } => string_at(path)
                .and_then(email_domain)
                .is_some_and(|d| domains.contains(&d)),
            Kind::MaxCalls(_) => true,
            Kind::Executor(roles) => match exec {
                None => true,
                Some(e) => match e.recipient {
                    Recipient::Role(r) => {
                        roles.iter().any(|x| x == r) && e.executor_role == r.as_str()
                    }
                    Recipient::Agent(_) => false,
                },
            },
        }
    }
}

/// Decode `caveat` and evaluate it against `tool` and `args` (cjson object).
///
/// `None` iff the caveat fails to decode. A caveat whose scope does not match
/// holds. `MaxCalls` and `Executor` are not evaluated here and return
/// `Some(true)`. If `args` is not a valid cjson object, every path is absent.
#[must_use]
pub fn caveat_eval(caveat: &[u8], tool: &str, args: &[u8]) -> Option<bool> {
    let cv = decode_one(caveat)?;
    if !cv.scope_matches(tool) {
        return Some(true);
    }
    let doc = cjson::parse(args, true);
    Some(cv.holds(tool, doc.as_ref(), None))
}
