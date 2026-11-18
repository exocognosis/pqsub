//! Canonical JSON ("cjson", V2_DESIGN §14.2) and RFC 6901 pointers (§14.1).
//!
//! Acceptance is by round-trip: the input must parse under the restricted
//! RFC 8259 grammar *and* re-serialize canonically to exactly the input bytes.

use std::collections::HashSet;

/// Maximum size of tool-call arguments (top-level object).
pub const MAX_ARGS: usize = 8192;
/// Maximum size of a caveat value.
pub const MAX_VALUE: usize = 1024;
/// Maximum container depth (top-level container = 1).
pub const MAX_DEPTH: usize = 4;
const MAX_INT: i64 = (1i64 << 53) - 1;

/// A parsed cjson value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// `null`
    Null,
    /// `true` / `false`
    Bool(bool),
    /// Integer in [−(2⁵³−1), 2⁵³−1].
    Int(i64),
    /// String (decoded).
    Str(String),
    /// Array.
    Arr(Vec<Value>),
    /// Object, members in input order (canonical inputs are sorted).
    Obj(Vec<(String, Value)>),
}

/// Whether `bytes` is accepted as cjson. `object`: top level must be an object
/// (tool-call args, ≤ 8192 bytes); otherwise any type (caveat value, ≤ 1024 bytes).
#[must_use]
pub fn cjson_valid(bytes: &[u8], object: bool) -> bool {
    parse(bytes, object).is_some()
}

/// Parse and validate cjson; `None` if not accepted.
#[must_use]
pub fn parse(bytes: &[u8], object: bool) -> Option<Value> {
    let max = if object { MAX_ARGS } else { MAX_VALUE };
    if bytes.len() > max {
        return None;
    }
    let s = std::str::from_utf8(bytes).ok()?;
    let mut p = Parser {
        b: s.as_bytes(),
        i: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return None;
    }
    if object && !matches!(v, Value::Obj(_)) {
        return None;
    }
    if canonical(&v) != bytes {
        return None;
    }
    Some(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i += 1;
        Some(c)
    }
    fn eat(&mut self, c: u8) -> Option<()> {
        (self.bump()? == c).then_some(())
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    fn lit(&mut self, word: &[u8]) -> Option<()> {
        let end = self.i.checked_add(word.len())?;
        (self.b.get(self.i..end)? == word).then(|| self.i = end)
    }

    /// `depth` = number of enclosing containers.
    fn value(&mut self, depth: usize) -> Option<Value> {
        match self.peek()? {
            b'{' => {
                let d = depth.checked_add(1).filter(|&d| d <= MAX_DEPTH)?;
                self.i += 1;
                self.ws();
                let mut members = Vec::new();
                let mut seen = HashSet::new();
                if self.peek()? == b'}' {
                    self.i += 1;
                    return Some(Value::Obj(members));
                }
                loop {
                    self.ws();
                    let k = self.string()?;
                    if !seen.insert(k.clone()) {
                        return None;
                    }
                    self.ws();
                    self.eat(b':')?;
                    self.ws();
                    let v = self.value(d)?;
                    members.push((k, v));
                    self.ws();
                    match self.bump()? {
                        b',' => {}
                        b'}' => return Some(Value::Obj(members)),
                        _ => return None,
                    }
                }
            }
            b'[' => {
                let d = depth.checked_add(1).filter(|&d| d <= MAX_DEPTH)?;
                self.i += 1;
                self.ws();
                let mut items = Vec::new();
                if self.peek()? == b']' {
                    self.i += 1;
                    return Some(Value::Arr(items));
                }
                loop {
                    self.ws();
                    items.push(self.value(d)?);
                    self.ws();
                    match self.bump()? {
                        b',' => {}
                        b']' => return Some(Value::Arr(items)),
                        _ => return None,
                    }
                }
            }
            b'"' => self.string().map(Value::Str),
            b't' => self.lit(b"true").map(|()| Value::Bool(true)),
            b'f' => self.lit(b"false").map(|()| Value::Bool(false)),
            b'n' => self.lit(b"null").map(|()| Value::Null),
            b'-' | b'0'..=b'9' => self.number().map(Value::Int),
            _ => None,
        }
    }

    fn number(&mut self) -> Option<i64> {
        let neg = self.peek()? == b'-';
        if neg {
            self.i += 1;
        }
        let mut mag: i64 = 0;
        match self.bump()? {
            b'0' => {}
            c @ b'1'..=b'9' => {
                mag = i64::from(c - b'0');
                while let Some(c @ b'0'..=b'9') = self.peek() {
                    self.i += 1;
                    mag = mag
                        .checked_mul(10)?
                        .checked_add(i64::from(c - b'0'))
                        .filter(|&m| m <= MAX_INT)?;
                }
            }
            _ => return None,
        }
        // Fractions and exponents are not part of the cjson grammar.
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return None;
        }
        if neg && mag == 0 {
            return None; // -0
        }
        Some(if neg { -mag } else { mag })
    }

    fn hex4(&mut self) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..4 {
            let d = char::from(self.bump()?).to_digit(16)?;
            v = (v << 4) | d;
        }
        Some(v)
    }

    fn string(&mut self) -> Option<String> {
        self.eat(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = self.bump()?;
            match c {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => {
                    let ch = match self.bump()? {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let u = self.hex4()?;
                            let cp = match u {
                                0xD800..=0xDBFF => {
                                    self.eat(b'\\')?;
                                    self.eat(b'u')?;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..=0xDFFF).contains(&lo) {
                                        return None;
                                    }
                                    0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00)
                                }
                                0xDC00..=0xDFFF => return None,
                                _ => u,
                            };
                            char::from_u32(cp)?
                        }
                        _ => return None,
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                0x00..=0x1F => return None,
                _ => out.push(c),
            }
        }
    }
}

/// Canonical serialization of `v` (§14.2).
#[must_use]
pub fn canonical(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write(v, &mut out);
    out
}

fn write(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Int(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Value::Str(s) => write_str(s, out),
        Value::Arr(items) => {
            out.push(b'[');
            for (k, it) in items.iter().enumerate() {
                if k > 0 {
                    out.push(b',');
                }
                write(it, out);
            }
            out.push(b']');
        }
        Value::Obj(members) => {
            let mut sorted: Vec<&(String, Value)> = members.iter().collect();
            sorted.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push(b'{');
            for (k, (key, val)) in sorted.into_iter().enumerate() {
                if k > 0 {
                    out.push(b',');
                }
                write_str(key, out);
                out.push(b':');
                write(val, out);
            }
            out.push(b'}');
        }
    }
}

fn write_str(s: &str, out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    for &b in s.as_bytes() {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0C => out.extend_from_slice(b"\\f"),
            0x0A => out.extend_from_slice(b"\\n"),
            0x0D => out.extend_from_slice(b"\\r"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x00..=0x1F => {
                out.extend_from_slice(b"\\u00");
                out.push(HEX[usize::from(b >> 4)]);
                out.push(HEX[usize::from(b & 0xF)]);
            }
            _ => out.push(b),
        }
    }
    out.push(b'"');
}

/// Pointer syntax (§14.1): empty or starting with `/`; every `~` followed by `0` or `1`.
#[must_use]
pub fn valid_pointer(p: &str) -> bool {
    if !(p.is_empty() || p.starts_with('/')) {
        return false;
    }
    let b = p.as_bytes();
    b.iter()
        .enumerate()
        .all(|(i, &c)| c != b'~' || matches!(b.get(i + 1), Some(b'0' | b'1')))
}

fn unescape_token(t: &str) -> Option<String> {
    let mut out = String::with_capacity(t.len());
    let mut it = t.chars();
    while let Some(c) = it.next() {
        if c == '~' {
            match it.next()? {
                '0' => out.push('~'),
                '1' => out.push('/'),
                _ => return None,
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

fn array_index(t: &str) -> Option<usize> {
    let b = t.as_bytes();
    match b {
        [b'0'] => Some(0),
        [b'1'..=b'9', rest @ ..] if rest.iter().all(u8::is_ascii_digit) => {
            b.iter().try_fold(0usize, |acc, &d| {
                acc.checked_mul(10)?.checked_add(usize::from(d - b'0'))
            })
        }
        _ => None,
    }
}

/// RFC 6901 evaluation (§14.1). `None` = absent (or invalid pointer).
#[must_use]
pub fn pointer<'v>(doc: &'v Value, ptr: &str) -> Option<&'v Value> {
    if !valid_pointer(ptr) {
        return None;
    }
    if ptr.is_empty() {
        return Some(doc);
    }
    let mut cur = doc;
    for raw in ptr.get(1..)?.split('/') {
        let tok = unescape_token(raw)?;
        cur = match cur {
            Value::Obj(m) => &m.iter().find(|(k, _)| *k == tok)?.1,
            Value::Arr(a) => a.get(array_index(&tok)?)?,
            _ => return None,
        };
    }
    Some(cur)
}
