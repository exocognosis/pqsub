//! Caveats: a fixed, small, monotone set of restrictions carried by grants
//! (V2_DESIGN §6, §14.3–14.4). Every caveat of every grant in a chain must hold.

use crate::cjson::{self, Value};
use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::manifest::Recipient;

/// Max items in a caveat list.
pub const MAX_LIST: usize = 32;

/// Which tool calls a caveat applies to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Every call.
    All,
    /// Only calls to this tool.
    Tool(String),
}

/// The restriction itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaveatKind {
    /// `call.tool` ∈ set (scope must be [`Scope::All`]).
    ToolAllow(Vec<String>),
    /// Value at `path` byte-equals canonical `value`.
    ArgEq {
        /// RFC 6901 pointer.
        path: String,
        /// Canonical cjson bytes.
        value: Vec<u8>,
    },
    /// Value at `path` equals one of `values`.
    ArgOneOf {
        /// RFC 6901 pointer.
        path: String,
        /// Canonical cjson bytes.
        values: Vec<Vec<u8>>,
    },
    /// Integer at `path` within `[min, max]`.
    IntRange {
        /// RFC 6901 pointer.
        path: String,
        /// Inclusive minimum.
        min: i64,
        /// Inclusive maximum.
        max: i64,
    },
    /// String at `path` is a valid absolute path segment-wise under `root`.
    PathUnder {
        /// RFC 6901 pointer.
        path: String,
        /// Absolute root path.
        root: String,
    },
    /// String at `path` is a URL whose `scheme://host:port` origin is listed.
    UrlOrigin {
        /// RFC 6901 pointer.
        path: String,
        /// Canonical origins `scheme://host:port`.
        origins: Vec<String>,
    },
    /// String at `path` is an email address whose domain is listed.
    EmailDomain {
        /// RFC 6901 pointer.
        path: String,
        /// Lowercase domains.
        domains: Vec<String>,
    },
    /// At most `n` executed calls use this grant (requires `Executor` in the same grant).
    MaxCalls(u32),
    /// Recipient must be one of these roles, and the executor must hold it.
    Executor(Vec<String>),
}

/// A scoped restriction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caveat {
    /// Applicability.
    pub scope: Scope,
    /// Restriction.
    pub kind: CaveatKind,
}

/// Tool-name syntax: 1..=64 of `[a-z0-9_.-]`.
#[must_use]
pub fn valid_tool_name(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_.-".contains(&c))
}

/// Host syntax (§14.4): lowercase LDH labels, ≤ 253 bytes, last label not all-digit.
#[must_use]
pub fn valid_host(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = h.split('.').collect();
    let ok = labels.iter().all(|l| {
        (1..=63).contains(&l.len())
            && l.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    });
    ok && labels
        .last()
        .is_some_and(|l| !l.bytes().all(|c| c.is_ascii_digit()))
}

/// Segments of a valid absolute path, or `None`.
#[must_use]
pub fn abs_path_segments(s: &str) -> Option<Vec<&str>> {
    let rest = s.strip_prefix('/')?;
    if s.contains('\\') || s.contains('\0') {
        return None;
    }
    if rest.is_empty() {
        return Some(vec![]);
    }
    let segs: Vec<&str> = rest.split('/').collect();
    segs.iter()
        .all(|g| !g.is_empty() && *g != "." && *g != "..")
        .then_some(segs)
}

fn parse_port(p: &str) -> Option<u16> {
    if p.is_empty() || p.len() > 5 || p.starts_with('0') || !p.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    p.parse::<u32>()
        .ok()
        .filter(|v| (1..=65535).contains(v))
        .and_then(|v| u16::try_from(v).ok())
}

/// Canonical origin `scheme://host:port` of a URL, or `None` if it fails strict parsing.
#[must_use]
pub fn url_origin(s: &str) -> Option<String> {
    let (scheme, rest, default) = if let Some(r) = s.strip_prefix("https://") {
        ("https", r, 443u16)
    } else {
        let r = s.strip_prefix("http://")?;
        ("http", r, 80u16)
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let auth = &rest[..end];
    if auth.contains('@') {
        return None;
    }
    let (host, port) = match auth.split_once(':') {
        Some((h, p)) => (h, parse_port(p)?),
        None => (auth, default),
    };
    valid_host(host).then(|| format!("{scheme}://{host}:{port}"))
}

fn valid_origin_spec(o: &str) -> bool {
    let Some((scheme, rest)) = o.split_once("://") else {
        return false;
    };
    let Some((host, port)) = rest.split_once(':') else {
        return false;
    };
    (scheme == "http" || scheme == "https") && valid_host(host) && parse_port(port).is_some()
}

/// Lowercased domain of a strictly-parsed email address, or `None`.
#[must_use]
pub fn email_domain(s: &str) -> Option<String> {
    if !s.bytes().all(|c| (0x21..=0x7e).contains(&c)) {
        return None;
    }
    let (local, domain) = s.split_once('@')?;
    if local.is_empty() || domain.contains('@') {
        return None;
    }
    let d = domain.to_ascii_lowercase();
    valid_host(&d).then_some(d)
}

fn list_ok<T>(v: &[T]) -> bool {
    (1..=MAX_LIST).contains(&v.len())
}

impl Caveat {
    /// Structural validation shared by encode (→ `InvalidField`) and decode (→ `Decode`).
    fn validate(&self) -> core::result::Result<(), &'static str> {
        if let Scope::Tool(t) = &self.scope {
            if !valid_tool_name(t) {
                return Err("caveat scope tool name");
            }
        }
        let path_ok = |p: &str| p.len() <= 255 && cjson::validate_pointer(p).is_ok();
        let val_ok = |v: &[u8]| cjson::parse_canonical(v, false).is_ok();
        let ok = match &self.kind {
            CaveatKind::ToolAllow(t) => {
                self.scope == Scope::All && list_ok(t) && t.iter().all(|x| valid_tool_name(x))
            }
            CaveatKind::ArgEq { path, value } => path_ok(path) && val_ok(value),
            CaveatKind::ArgOneOf { path, values } => {
                path_ok(path) && list_ok(values) && values.iter().all(|v| val_ok(v))
            }
            CaveatKind::IntRange { path, min, max } => path_ok(path) && min <= max,
            CaveatKind::PathUnder { path, root } => {
                path_ok(path) && root.len() <= 65535 && abs_path_segments(root).is_some()
            }
            CaveatKind::UrlOrigin { path, origins } => {
                path_ok(path)
                    && list_ok(origins)
                    && origins
                        .iter()
                        .all(|o| o.len() <= 255 && valid_origin_spec(o))
            }
            CaveatKind::EmailDomain { path, domains } => {
                path_ok(path) && list_ok(domains) && domains.iter().all(|d| valid_host(d))
            }
            CaveatKind::MaxCalls(n) => *n >= 1,
            CaveatKind::Executor(roles) => {
                list_ok(roles) && roles.iter().all(|r| (1..=64).contains(&r.len()))
            }
        };
        if ok {
            Ok(())
        } else {
            Err("caveat parameters invalid")
        }
    }

    pub(crate) fn write(&self, w: &mut Writer) -> Result<()> {
        self.validate().map_err(Error::InvalidField)?;
        let ty = match &self.kind {
            CaveatKind::ToolAllow(_) => 1,
            CaveatKind::ArgEq { .. } => 2,
            CaveatKind::ArgOneOf { .. } => 3,
            CaveatKind::IntRange { .. } => 4,
            CaveatKind::PathUnder { .. } => 5,
            CaveatKind::UrlOrigin { .. } => 6,
            CaveatKind::EmailDomain { .. } => 7,
            CaveatKind::MaxCalls(_) => 8,
            CaveatKind::Executor(_) => 9,
        };
        w.u8(ty);
        match &self.scope {
            Scope::All => w.u8(0),
            Scope::Tool(t) => {
                w.u8(1);
                w.str_u8(t);
            }
        }
        let list = |w: &mut Writer, v: &[String]| {
            w.u8(v.len() as u8);
            for s in v {
                w.str_u8(s);
            }
        };
        match &self.kind {
            CaveatKind::ToolAllow(t) => list(w, t),
            CaveatKind::ArgEq { path, value } => {
                w.str_u8(path);
                w.u16(value.len() as u16);
                w.bytes(value);
            }
            CaveatKind::ArgOneOf { path, values } => {
                w.str_u8(path);
                w.u8(values.len() as u8);
                for v in values {
                    w.u16(v.len() as u16);
                    w.bytes(v);
                }
            }
            CaveatKind::IntRange { path, min, max } => {
                w.str_u8(path);
                w.u64(*min as u64);
                w.u64(*max as u64);
            }
            CaveatKind::PathUnder { path, root } => {
                w.str_u8(path);
                w.str_u16(root);
            }
            CaveatKind::UrlOrigin { path, origins: v }
            | CaveatKind::EmailDomain { path, domains: v } => {
                w.str_u8(path);
                list(w, v);
            }
            CaveatKind::MaxCalls(n) => w.u32(*n),
            CaveatKind::Executor(r) => list(w, r),
        }
        Ok(())
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let ty = r.u8()?;
        let scope = match r.u8()? {
            0 => Scope::All,
            1 => Scope::Tool(r.str_u8(1, 64)?),
            _ => return Err(Error::Decode("caveat scope tag")),
        };
        let list = |r: &mut Reader<'_>, min: usize, max: usize| -> Result<Vec<String>> {
            let n = r.u8()? as usize;
            if !(1..=MAX_LIST).contains(&n) {
                return Err(Error::Decode("caveat list length"));
            }
            (0..n).map(|_| r.str_u8(min, max)).collect()
        };
        let path = |r: &mut Reader<'_>| r.str_u8(0, 255);
        let value = |r: &mut Reader<'_>| -> Result<Vec<u8>> {
            let n = r.u16()? as usize;
            Ok(r.take(n)?.to_vec())
        };
        let kind = match ty {
            1 => CaveatKind::ToolAllow(list(r, 1, 64)?),
            2 => CaveatKind::ArgEq {
                path: path(r)?,
                value: value(r)?,
            },
            3 => {
                let path = path(r)?;
                let n = r.u8()? as usize;
                if !(1..=MAX_LIST).contains(&n) {
                    return Err(Error::Decode("caveat list length"));
                }
                let values = (0..n).map(|_| value(r)).collect::<Result<_>>()?;
                CaveatKind::ArgOneOf { path, values }
            }
            4 => CaveatKind::IntRange {
                path: path(r)?,
                min: r.u64()? as i64,
                max: r.u64()? as i64,
            },
            5 => CaveatKind::PathUnder {
                path: path(r)?,
                root: r.str_u16(0, 65535)?,
            },
            6 => CaveatKind::UrlOrigin {
                path: path(r)?,
                origins: list(r, 0, 255)?,
            },
            7 => CaveatKind::EmailDomain {
                path: path(r)?,
                domains: list(r, 0, 255)?,
            },
            8 => CaveatKind::MaxCalls(r.u32()?),
            9 => CaveatKind::Executor(list(r, 1, 64)?),
            _ => return Err(Error::Decode("unknown caveat type")),
        };
        let c = Self { scope, kind };
        c.validate().map_err(Error::Decode)?;
        Ok(c)
    }

    /// Standalone canonical encoding.
    ///
    /// # Errors
    /// [`Error::InvalidField`].
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        self.write(&mut w)?;
        Ok(w.into_vec())
    }

    /// Strict standalone decode.
    ///
    /// # Errors
    /// [`Error::Decode`].
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let c = Self::read(&mut r)?;
        r.finish()?;
        Ok(c)
    }

    /// Whether the scope covers `tool`.
    #[must_use]
    pub fn applies_to(&self, tool: &str) -> bool {
        match &self.scope {
            Scope::All => true,
            Scope::Tool(t) => t == tool,
        }
    }

    /// Evaluate against a call. `MaxCalls` always holds here (budgets are
    /// checked separately). A caveat whose scope does not match holds.
    #[must_use]
    pub fn holds(
        &self,
        tool: &str,
        args: &Value,
        recipient: &Recipient,
        executor_role: &str,
    ) -> bool {
        if !self.applies_to(tool) {
            return true;
        }
        let at = |p: &str| cjson::pointer(args, p);
        let s_at = |p: &str| match at(p) {
            Some(Value::Str(s)) => Some(s.as_str()),
            _ => None,
        };
        match &self.kind {
            CaveatKind::ToolAllow(t) => t.iter().any(|x| x == tool),
            CaveatKind::ArgEq { path, value } => {
                at(path).is_some_and(|v| cjson::encode(v) == *value)
            }
            CaveatKind::ArgOneOf { path, values } => at(path).is_some_and(|v| {
                let e = cjson::encode(v);
                values.contains(&e)
            }),
            CaveatKind::IntRange { path, min, max } => {
                matches!(at(path), Some(Value::Int(i)) if min <= i && i <= max)
            }
            CaveatKind::PathUnder { path, root } => {
                s_at(path).is_some_and(|s| match (abs_path_segments(s), abs_path_segments(root)) {
                    (Some(v), Some(r)) => v.starts_with(&r),
                    _ => false,
                })
            }
            CaveatKind::UrlOrigin { path, origins } => s_at(path)
                .and_then(url_origin)
                .is_some_and(|o| origins.contains(&o)),
            CaveatKind::EmailDomain { path, domains } => s_at(path)
                .and_then(email_domain)
                .is_some_and(|d| domains.contains(&d)),
            CaveatKind::MaxCalls(_) => true,
            CaveatKind::Executor(roles) => match recipient {
                Recipient::Role(r) => roles.iter().any(|x| x == r) && r == executor_role,
                Recipient::Agent(_) => false,
            },
        }
    }
}
