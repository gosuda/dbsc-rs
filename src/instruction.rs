//! Session instruction JSON model (DBSC spec 9.6-9.9).

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// A scope rule inside `SessionScope::scope_specification`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeRule {
    /// "include" or "exclude".
    #[serde(rename = "type")]
    pub rule_type: String,
    /// Optional domain the rule applies to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Optional path the rule applies to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl ScopeRule {
    /// Create an "include" rule.
    pub fn include(domain: Option<String>, path: Option<String>) -> Self {
        ScopeRule { rule_type: "include".into(), domain, path }
    }

    /// Create an "exclude" rule.
    pub fn exclude(domain: Option<String>, path: Option<String>) -> Self {
        ScopeRule { rule_type: "exclude".into(), domain, path }
    }
}

/// Which requests carry session credentials (spec 9.8).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionScope {
    /// Session origin. Serialized as `origin`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// Whether all subdomains/sites are included.
    pub include_site: bool,
    /// Fine-grained include/exclude rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope_specification: Vec<ScopeRule>,
}

/// A credential the browser must send (spec 9.9).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionCredential {
    /// Credential type; currently always "cookie".
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Cookie name.
    pub name: String,
    /// Optional cookie attributes string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<String>,
}

impl SessionCredential {
    /// Create a cookie credential.
    pub fn cookie(name: impl Into<String>, attributes: Option<String>) -> Self {
        SessionCredential { cred_type: "cookie".into(), name: name.into(), attributes }
    }
}

/// A session instruction sent to the client (spec 9.6-9.7).
///
/// When `continue_session` is `false`, serialization produces only
/// `{"continue": false}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(into = "SessionInstructionRepr", from = "SessionInstructionRepr")]
pub struct SessionInstruction {
    /// Session identifier. Omitted when `continue_session` is false.
    pub session_identifier: String,
    /// Refresh endpoint URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_url: Option<String>,
    /// Whether the session continues. `false` means terminate (spec 9.6).
    pub continue_session: bool,
    /// Session scope.
    pub scope: SessionScope,
    /// Credentials the client must present.
    pub credentials: Vec<SessionCredential>,
    /// Origins allowed to trigger refreshes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_refresh_initiators: Vec<String>,
}

impl SessionInstruction {
    /// Instruction terminating the session (`{"continue": false}`).
    pub fn terminate() -> Self {
        SessionInstruction {
            session_identifier: String::new(),
            refresh_url: None,
            continue_session: false,
            scope: SessionScope::default(),
            credentials: Vec::new(),
            allowed_refresh_initiators: Vec::new(),
        }
    }

    /// Serialize to a JSON string.
    pub fn to_json_string(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

/// Wire representation: `continue: false` collapses to only that key.
#[derive(Serialize, Deserialize)]
struct SessionInstructionRepr {
    #[serde(rename = "continue")]
    continue_session: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<SessionScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credentials: Option<Vec<SessionCredential>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allowed_refresh_initiators: Vec<String>,
}

impl From<SessionInstruction> for SessionInstructionRepr {
    fn from(i: SessionInstruction) -> Self {
        if i.continue_session {
            SessionInstructionRepr {
                continue_session: true,
                session_identifier: Some(i.session_identifier),
                refresh_url: i.refresh_url,
                scope: Some(i.scope),
                credentials: Some(i.credentials),
                allowed_refresh_initiators: i.allowed_refresh_initiators,
            }
        } else {
            SessionInstructionRepr {
                continue_session: false,
                session_identifier: None,
                refresh_url: None,
                scope: None,
                credentials: None,
                allowed_refresh_initiators: Vec::new(),
            }
        }
    }
}

impl From<SessionInstructionRepr> for SessionInstruction {
    fn from(r: SessionInstructionRepr) -> Self {
        SessionInstruction {
            session_identifier: r.session_identifier.unwrap_or_default(),
            refresh_url: r.refresh_url,
            continue_session: r.continue_session,
            scope: r.scope.unwrap_or_default(),
            credentials: r.credentials.unwrap_or_default(),
            allowed_refresh_initiators: r.allowed_refresh_initiators,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminate_serializes_minimally() {
        let json = SessionInstruction::terminate().to_json_string().unwrap();
        assert_eq!(json, "{\"continue\":false}");
    }

    #[test]
    fn full_instruction_keys() {
        let instr = SessionInstruction {
            session_identifier: "sid".into(),
            refresh_url: Some("/dbsc/refresh".into()),
            continue_session: true,
            scope: SessionScope {
                origin: Some("https://example.com".into()),
                include_site: false,
                scope_specification: vec![
                    ScopeRule::include(None, Some("/app".into())),
                    ScopeRule::exclude(None, Some("/app/static".into())),
                ],
            },
            credentials: vec![SessionCredential::cookie("auth_cookie", None)],
            allowed_refresh_initiators: vec![],
        };
        let json = instr.to_json_string().unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["session_identifier"], "sid");
        assert_eq!(v["refresh_url"], "/dbsc/refresh");
        assert_eq!(v["continue"], true);
        assert_eq!(v["scope"]["origin"], "https://example.com");
        assert_eq!(v["scope"]["include_site"], false);
        assert_eq!(v["scope"]["scope_specification"][0]["type"], "include");
        assert_eq!(v["scope"]["scope_specification"][1]["type"], "exclude");
        assert_eq!(v["credentials"][0]["type"], "cookie");
        assert_eq!(v["credentials"][0]["name"], "auth_cookie");
        // empty allowed_refresh_initiators omitted
        assert!(v.get("allowed_refresh_initiators").is_none());
    }

    #[test]
    fn refresh_url_omitted_when_none() {
        let instr = SessionInstruction {
            session_identifier: "sid".into(),
            refresh_url: None,
            continue_session: true,
            scope: SessionScope::default(),
            credentials: vec![],
            allowed_refresh_initiators: vec![],
        };
        let v: serde_json::Value =
            serde_json::from_str(&instr.to_json_string().unwrap()).unwrap();
        assert!(v.get("refresh_url").is_none());
    }

    #[test]
    fn terminate_roundtrip() {
        let instr: SessionInstruction =
            serde_json::from_str("{\"continue\":false}").unwrap();
        assert!(!instr.continue_session);
    }

    #[test]
    fn full_instruction_snapshot() {
        let instr = SessionInstruction {
            session_identifier: "sess-42".into(),
            refresh_url: Some("https://example.com/dbsc/refresh".into()),
            continue_session: true,
            scope: SessionScope {
                origin: Some("https://example.com".into()),
                include_site: true,
                scope_specification: vec![
                    ScopeRule::include(Some("example.com".into()), Some("/app".into())),
                    ScopeRule::exclude(None, Some("/app/static".into())),
                ],
            },
            credentials: vec![
                SessionCredential::cookie("auth", Some("SameSite=Lax".into())),
                SessionCredential::cookie("csrf", None),
            ],
            allowed_refresh_initiators: vec!["https://example.com".into()],
        };
        let json = instr.to_json_string().unwrap();
        let expected = r#"{"continue":true,"session_identifier":"sess-42","refresh_url":"https://example.com/dbsc/refresh","scope":{"origin":"https://example.com","include_site":true,"scope_specification":[{"type":"include","domain":"example.com","path":"/app"},{"type":"exclude","path":"/app/static"}]},"credentials":[{"type":"cookie","name":"auth","attributes":"SameSite=Lax"},{"type":"cookie","name":"csrf"}],"allowed_refresh_initiators":["https://example.com"]}"#;
        assert_eq!(json, expected);
        // And it parses back to the same value.
        let parsed: SessionInstruction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, instr);
    }
}
