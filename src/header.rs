//! RFC 9651 structured field serialization and parsing for DBSC headers.

/// Coarse-grained reason a session was skipped by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The refresh endpoint was unreachable.
    Unreachable,
    /// The server returned an error.
    ServerError,
    /// The client's session quota was exceeded.
    QuotaExceeded,
}

impl SkipReason {
    fn from_token(token: &str) -> Option<Self> {
        match token {
            "unreachable" => Some(SkipReason::Unreachable),
            "server_error" => Some(SkipReason::ServerError),
            "quota_exceeded" => Some(SkipReason::QuotaExceeded),
            _ => None,
        }
    }

    /// Token form used in the `Secure-Session-Skipped` header.
    pub fn as_token(&self) -> &'static str {
        match self {
            SkipReason::Unreachable => "unreachable",
            SkipReason::ServerError => "server_error",
            SkipReason::QuotaExceeded => "quota_exceeded",
        }
    }
}

/// A single parsed entry of the `Secure-Session-Skipped` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedEntry {
    /// Why the session was skipped.
    pub reason: SkipReason,
    /// Identifier of the skipped session.
    pub session_id: String,
}

/// Escape a value for inclusion in a quoted structured-field string.
fn sf_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out
}

/// Serialize a `Secure-Session-Registration` header value.
///
/// Produces, e.g. `(ES256 RS256);path="/dbsc/register";challenge="cv";authorization="ac"`.
/// `None`/empty optional parameters are omitted.
pub fn registration_header(
    algs: &[&str],
    path: Option<&str>,
    challenge: Option<&str>,
    authorization: Option<&str>,
    provider_key: Option<&str>,
    provider_session_id: Option<&str>,
    provider_url: Option<&str>,
) -> String {
    let mut out = String::from("(");
    out.push_str(&algs.join(" "));
    out.push(')');
    let mut param = |key: &str, value: Option<&str>| {
        if let Some(v) = value
            && !v.is_empty()
        {
            out.push_str(&format!(";{key}=\"{}\"", sf_escape(v)));
        }
    };
    param("path", path);
    param("challenge", challenge);
    param("authorization", authorization);
    param("provider_key", provider_key);
    param("provider_session_id", provider_session_id);
    param("provider_url", provider_url);
    out
}

/// Serialize a `Secure-Session-Challenge` header value: `"value";id="session_id"`.
pub fn challenge_header(value: &str, session_id: &str) -> String {
    format!("\"{}\";id=\"{}\"", sf_escape(value), sf_escape(session_id))
}

/// Serialize a `Secure-Session-Response` header value: `"jwt"`.
pub fn session_response_header(jwt: &str) -> String {
    format!("\"{}\"", sf_escape(jwt))
}

/// Serialize a `Sec-Secure-Session-Id` header value: `"id"`.
pub fn session_id_header(id: &str) -> String {
    format!("\"{}\"", sf_escape(id))
}

/// Serialize a `Secure-Session-Skipped` header value (sf-list).
pub fn session_skipped_header(entries: &[SkippedEntry]) -> String {
    entries
        .iter()
        .map(|e| {
            format!(
                "{};session_identifier=\"{}\"",
                e.reason.as_token(),
                sf_escape(&e.session_id)
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Parse a quoted structured-field string, returning the unescaped content.
/// Leading/trailing whitespace around the whole value is ignored; trailing
/// characters after the closing quote cause failure.
fn parse_quoted(value: &str) -> Option<String> {
    let value = value.trim().strip_prefix('"')?;
    let mut out = String::with_capacity(value.len());
    let mut chars = value.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => {
                return if value[i + 1..].trim().is_empty() {
                    Some(out)
                } else {
                    None
                };
            }
            '\\' => {
                let (_, escaped) = chars.next()?;
                out.push(escaped);
            }
            c => out.push(c),
        }
    }
    None
}

/// Parse a `Secure-Session-Response` header value and extract the JWT.
pub fn parse_session_response(header: &str) -> Option<String> {
    parse_quoted(header)
}

/// Parse a `Sec-Secure-Session-Id` header value and extract the session id.
pub fn parse_session_id(header: &str) -> Option<String> {
    parse_quoted(header)
}

/// Parse a `Secure-Session-Skipped` header value (sf-list).
///
/// Each list item is a reason token with a `session_identifier="..."`
/// parameter. Only the spec-defined reason tokens are accepted; items with
/// unknown tokens or without a `session_identifier` parameter are skipped.
pub fn parse_session_skipped(header: &str) -> Vec<SkippedEntry> {
    let mut entries = Vec::new();
    for item in header.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let mut parts = item.split(';');
        let reason = match SkipReason::from_token(parts.next().unwrap_or("").trim()) {
            Some(r) => r,
            None => continue,
        };
        let mut session_id = None;
        for param in parts {
            let mut kv = param.splitn(2, '=');
            let key = kv.next().unwrap_or("").trim();
            let value = match kv.next() {
                Some(v) => v.trim(),
                None => continue,
            };
            if key == "session_identifier" {
                session_id = parse_quoted(value);
            }
        }
        if let Some(session_id) = session_id {
            entries.push(SkippedEntry { reason, session_id });
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_header_full() {
        let h = registration_header(
            &["ES256", "RS256"],
            Some("/dbsc/register"),
            Some("cv"),
            Some("ac"),
            Some("pk"),
            Some("psid"),
            Some("https://idp.example"),
        );
        assert_eq!(
            h,
            "(ES256 RS256);path=\"/dbsc/register\";challenge=\"cv\";authorization=\"ac\";provider_key=\"pk\";provider_session_id=\"psid\";provider_url=\"https://idp.example\""
        );
    }

    #[test]
    fn registration_header_minimal() {
        let h = registration_header(&["ES256"], None, Some("cv"), None, None, None, None);
        assert_eq!(h, "(ES256);challenge=\"cv\"");
    }

    #[test]
    fn challenge_and_simple_headers() {
        assert_eq!(challenge_header("cv", "sid"), "\"cv\";id=\"sid\"");
        assert_eq!(session_response_header("jwt.token.here"), "\"jwt.token.here\"");
        assert_eq!(session_id_header("id"), "\"id\"");
    }

    #[test]
    fn parse_response_roundtrip() {
        let h = session_response_header("abc.def.ghi");
        assert_eq!(parse_session_response(&h).as_deref(), Some("abc.def.ghi"));
    }

    #[test]
    fn parse_id_roundtrip() {
        let h = session_id_header("sid-123");
        assert_eq!(parse_session_id(&h).as_deref(), Some("sid-123"));
    }

    #[test]
    fn parse_rejects_unquoted() {
        assert_eq!(parse_session_response("not-quoted"), None);
        assert_eq!(parse_session_response("\"ok\" extra"), None);
    }

    #[test]
    fn parse_escaped() {
        let h = session_response_header("a\\\"b");
        assert_eq!(parse_session_response(&h).as_deref(), Some("a\\\"b"));
    }

    #[test]
    fn parse_quoted_escaped_quotes_and_backslash() {
        // Raw header text: "a\"b\\c" (quoted, escaped quote, escaped backslash).
        assert_eq!(parse_quoted(r#""a\"b\\c""#).as_deref(), Some("a\"b\\c"));
        // Unterminated escape or string fails.
        assert_eq!(parse_quoted("\"abc\\"), None);
        assert_eq!(parse_quoted("\"abc"), None);
    }

    #[test]
    fn registration_header_escapes_special_chars() {
        let h = registration_header(
            &["ES256"],
            Some("/reg"),
            Some("cha\"lle\\nge"),
            None,
            None,
            None,
            None,
        );
        assert_eq!(h, "(ES256);path=\"/reg\";challenge=\"cha\\\"lle\\\\nge\"");
    }

    #[test]
    fn challenge_header_escapes_and_roundtrips() {
        let h = challenge_header("va\"l", "s\\id");
        assert_eq!(h, "\"va\\\"l\";id=\"s\\\\id\"");
        // The value part parses back to the original.
        let value_part = h.split(';').next().unwrap();
        assert_eq!(parse_quoted(value_part).as_deref(), Some("va\"l"));
    }

    #[test]
    fn skipped_roundtrip() {
        let entries = vec![
            SkippedEntry {
                reason: SkipReason::Unreachable,
                session_id: "123".into(),
            },
            SkippedEntry {
                reason: SkipReason::QuotaExceeded,
                session_id: "456".into(),
            },
        ];
        let h = session_skipped_header(&entries);
        assert_eq!(
            h,
            "unreachable;session_identifier=\"123\", quota_exceeded;session_identifier=\"456\""
        );
        assert_eq!(parse_session_skipped(&h), entries);
    }

    #[test]
    fn skipped_mixed_valid_invalid() {
        let h = "unreachable;session_identifier=\"a\", bogus_token;session_identifier=\"b\", \
                 server_error, quota_exceeded;session_identifier=\"d\"";
        let got = parse_session_skipped(h);
        assert_eq!(
            got,
            vec![
                SkippedEntry {
                    reason: SkipReason::Unreachable,
                    session_id: "a".into()
                },
                SkippedEntry {
                    reason: SkipReason::QuotaExceeded,
                    session_id: "d".into()
                },
            ]
        );
    }
}
