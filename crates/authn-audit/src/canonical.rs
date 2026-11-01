//! Canonical JSON (AUD-02): the byte string that is hashed into the audit
//! chain and signed in webhook bodies.
//!
//! The encoding follows RFC 8785 (JSON Canonicalization Scheme) for the value
//! space this crate produces:
//! * object members sorted by the UTF-16 code units of their names,
//! * no insignificant whitespace,
//! * strings with the minimal JSON escaping (`"`, `\`, `\b \f \n \r \t`,
//!   other control characters as lowercase `\u00xx`; everything else
//!   verbatim UTF-8),
//! * numbers restricted to integers (`i64` / `u64`), written in plain
//!   decimal. Floating-point numbers are refused instead of relying on the
//!   ES6 number formatting rules, so that a value read back from PostgreSQL
//!   `jsonb` always reproduces the same bytes.
//!
//! The encoder never depends on the iteration order of `serde_json::Map`
//! (which changes with the `preserve_order` feature).

use serde_json::Value;

/// Maximum nesting depth accepted by the encoder (guards the recursion).
pub const MAX_DEPTH: usize = 32;

/// Why a value has no canonical form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    /// A floating-point number (only integers are canonicalized).
    #[error("non-integer number")]
    NonIntegerNumber,
    /// Nesting deeper than [`MAX_DEPTH`].
    #[error("value nested too deeply")]
    TooDeep,
}

/// Canonical JSON text of `value`.
pub fn to_canonical_string(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_value(value, &mut out, 0)?;
    Ok(out)
}

/// Canonical JSON bytes of `value`.
pub fn to_canonical_vec(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    to_canonical_string(value).map(String::into_bytes)
}

fn write_value(value: &Value, out: &mut String, depth: usize) -> Result<(), CanonicalError> {
    if depth > MAX_DEPTH {
        return Err(CanonicalError::TooDeep);
    }
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                return Err(CanonicalError::NonIntegerNumber);
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(item, out, depth + 1)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(item, out, depth + 1)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let code = u32::from(c);
                out.push_str("\\u00");
                for shift in [4_u32, 0] {
                    let nibble = (code >> shift) & 0xf;
                    let digit = usize::try_from(nibble)
                        .ok()
                        .and_then(|i| HEX.get(i))
                        .copied()
                        .unwrap_or(b'0');
                    out.push(char::from(digit));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Lowercase hexadecimal encoding (digests in canonical records and logs).
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0xf] {
            let digit = HEX.get(usize::from(nibble)).copied().unwrap_or(b'0');
            out.push(char::from(digit));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    #[test]
    fn aud_02_canonical_json_sorts_keys_and_has_no_whitespace() {
        let value = json!({"b": 1, "a": [true, null, "x"], "c": {"z": -5, "y": "é"}});
        assert_eq!(
            to_canonical_string(&value).unwrap(),
            r#"{"a":[true,null,"x"],"b":1,"c":{"y":"é","z":-5}}"#
        );
    }

    #[test]
    fn aud_02_canonical_json_escapes_minimally() {
        let value = json!("q\"b\\n\n\t\u{01}\u{1f}\u{7f}/<>");
        assert_eq!(
            to_canonical_string(&value).unwrap(),
            "\"q\\\"b\\\\n\\n\\t\\u0001\\u001f\u{7f}/<>\""
        );
    }

    #[test]
    fn aud_02_canonical_json_refuses_floats_and_deep_nesting() {
        assert_eq!(
            to_canonical_string(&json!({"a": 1.5})),
            Err(CanonicalError::NonIntegerNumber)
        );
        let mut deep = json!(1);
        for _ in 0..=MAX_DEPTH {
            deep = json!([deep]);
        }
        assert_eq!(to_canonical_string(&deep), Err(CanonicalError::TooDeep));
        assert_eq!(
            to_canonical_string(&json!(u64::MAX)).unwrap(),
            u64::MAX.to_string()
        );
    }

    #[test]
    fn aud_02_keys_sort_by_utf16_code_units() {
        // U+E000 (BMP, after surrogates) sorts after U+1F600 in UTF-16 order
        // although it sorts before it in UTF-8 / code point order.
        let value = json!({"\u{e000}": 1, "\u{1f600}": 2});
        assert_eq!(
            to_canonical_string(&value).unwrap(),
            "{\"\u{1f600}\":2,\"\u{e000}\":1}"
        );
    }

    #[test]
    fn aud_02_hex() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }

    fn arb_value() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(|i| json!(i)),
            any::<u64>().prop_map(|u| json!(u)),
            ".{0,12}".prop_map(Value::String),
        ];
        leaf.prop_recursive(4, 32, 6, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                prop::collection::btree_map("[a-z_]{1,8}", inner, 0..6)
                    .prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }

    proptest! {
        /// Parsing the canonical form and canonicalizing again yields the
        /// same bytes (what the chain verifier does with `jsonb` metadata).
        #[test]
        fn aud_02_canonical_form_is_a_fixed_point(value in arb_value()) {
            let first = to_canonical_string(&value).unwrap();
            let reparsed: Value = serde_json::from_str(&first).unwrap();
            prop_assert_eq!(&reparsed, &value);
            prop_assert_eq!(to_canonical_string(&reparsed).unwrap(), first);
        }
    }
}
