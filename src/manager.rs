//! DBSC protocol orchestration (registration, refresh, close).

use std::sync::Arc;

use crate::error::{Error, Result};
use crate::header;
use crate::instruction::{SessionCredential, SessionInstruction, SessionScope};
use crate::jwt;
use crate::session::{now_unix, Session, SessionState};
use crate::store::SessionStore;

/// Manager configuration.
#[derive(Debug, Clone)]
pub struct ManagerConfig {
    /// Cookie name. Defaults to `"session_id"`.
    pub cookie_name: String,
    /// Cookie path. Defaults to `"/"`.
    pub cookie_path: String,
    /// Optional cookie domain.
    pub cookie_domain: Option<String>,
    /// `SameSite` attribute. Defaults to `"Lax"`.
    pub same_site: String,
    /// Whether the cookie carries the `Secure` attribute.
    pub secure: bool,
    /// Browser cookie TTL in seconds. Defaults to 3600.
    pub cookie_ttl_seconds: u64,
    /// Backend session TTL in seconds (`None` = infinite).
    pub session_ttl_seconds: Option<u64>,
    /// Optional authorization value echoed in the registration header and
    /// verified against the proof JWT's `authorization` claim.
    pub authorization: Option<String>,
    /// Registration endpoint path. Defaults to `"/dbsc/register"`.
    pub register_path: String,
    /// Refresh endpoint path. Defaults to `"/dbsc/refresh"`.
    pub refresh_path: String,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        ManagerConfig {
            cookie_name: "session_id".into(),
            cookie_path: "/".into(),
            cookie_domain: None,
            same_site: "Lax".into(),
            secure: true,
            cookie_ttl_seconds: 3600,
            session_ttl_seconds: None,
            authorization: None,
            register_path: "/dbsc/register".into(),
            refresh_path: "/dbsc/refresh".into(),
        }
    }
}

/// Response produced by the manager; a wrapper layer translates it into
/// HTTP status, headers, and body.
#[derive(Debug, Clone, Default)]
pub struct ManagerResponse {
    /// HTTP status code.
    pub status_code: u16,
    /// Full `Set-Cookie` header value.
    pub set_cookie: Option<String>,
    /// `Secure-Session-Registration` header value.
    pub registration_header: Option<String>,
    /// `Secure-Session-Challenge` header value.
    pub challenge_header: Option<String>,
    /// JSON response body.
    pub body: Option<String>,
}

impl ManagerResponse {
    fn with_status(status_code: u16) -> Self {
        ManagerResponse {
            status_code,
            ..Default::default()
        }
    }

    /// 403 response carrying the current challenge of `session`
    /// (`Secure-Session-Challenge` with the mandatory `id` parameter).
    fn challenge_failure(session: &Session) -> Self {
        let challenge = session.challenge.as_deref().unwrap_or_default();
        ManagerResponse {
            status_code: 403,
            challenge_header: Some(header::challenge_header(challenge, &session.id)),
            ..Default::default()
        }
    }
}

/// High-level DBSC manager implementing the protocol flows.
pub struct Manager {
    store: Arc<dyn SessionStore>,
    config: ManagerConfig,
}

impl Manager {
    /// Create a manager backed by `store`.
    pub fn new(store: Arc<dyn SessionStore>, config: ManagerConfig) -> Self {
        Manager { store, config }
    }

    /// Build a `Set-Cookie` value for `session_id` with `max_age` seconds.
    fn build_cookie(&self, session_id: &str, max_age: u64) -> String {
        let mut c = format!(
            "{}={}; Path={}; Max-Age={}; HttpOnly",
            self.config.cookie_name, session_id, self.config.cookie_path, max_age
        );
        if self.config.secure {
            c.push_str("; Secure");
        }
        c.push_str(&format!("; SameSite={}", self.config.same_site));
        if let Some(domain) = &self.config.cookie_domain {
            c.push_str(&format!("; Domain={domain}"));
        }
        c
    }

    /// Refresh the session expiry from the configured TTL.
    fn apply_ttl(&self, session: &mut Session) {
        if let Some(ttl) = self.config.session_ttl_seconds {
            session.expires_at = Some(now_unix() + ttl as i64);
        }
    }

    /// Build the instruction body for a session.
    fn instruction_body(&self, session: &Session) -> Result<String> {
        SessionInstruction {
            session_identifier: session.id.clone(),
            refresh_url: Some(self.config.refresh_path.clone()),
            continue_session: true,
            scope: SessionScope::default(),
            credentials: vec![SessionCredential::cookie(
                self.config.cookie_name.clone(),
                None,
            )],
            allowed_refresh_initiators: Vec::new(),
        }
        .to_json_string()
    }

    /// Initiate a new DBSC session after a successful user login.
    ///
    /// Creates an `Active` session with a fresh challenge, persists it, and
    /// returns the session plus a response carrying the session cookie and
    /// the `Secure-Session-Registration` header.
    pub fn initiate(&self, user_id: &str) -> Result<(Session, ManagerResponse)> {
        let mut session = Session::new(user_id);
        session.challenge = Some(generate_challenge());
        self.apply_ttl(&mut session);
        self.store.create(&session)?;

        let resp = ManagerResponse {
            status_code: 200,
            set_cookie: Some(self.build_cookie(&session.id, self.config.cookie_ttl_seconds)),
            registration_header: Some(header::registration_header(
                &["ES256", "RS256"],
                Some(&self.config.register_path),
                session.challenge.as_deref(),
                self.config.authorization.as_deref(),
                None,
                None,
                None,
            )),
            challenge_header: None,
            body: None,
        };
        Ok((session, resp))
    }

    /// Handle a DBSC registration request.
    ///
    /// `cookie_session_id` comes from the session cookie,
    /// `session_response_header` from the `Secure-Session-Response` header.
    pub fn register(
        &self,
        cookie_session_id: &str,
        session_response_header: Option<&str>,
    ) -> Result<ManagerResponse> {
        let mut session = match self.store.get(cookie_session_id)? {
            Some(s) => s,
            None => return Ok(ManagerResponse::with_status(401)),
        };
        if session.state != SessionState::Active {
            return Ok(ManagerResponse::with_status(400));
        }

        let jwt_str = match session_response_header.and_then(header::parse_session_response) {
            Some(j) => j,
            None => return Ok(ManagerResponse::challenge_failure(&session)),
        };

        let proof = match jwt::verify_registration(&jwt_str) {
            Ok(p) => p,
            Err(_) => return Ok(ManagerResponse::challenge_failure(&session)),
        };
        if session.challenge.as_deref() != Some(proof.challenge.as_str()) {
            return Ok(ManagerResponse::challenge_failure(&session));
        }
        if self.config.authorization.is_some() && proof.authorization != self.config.authorization
        {
            return Ok(ManagerResponse::challenge_failure(&session));
        }

        // Bind the session to the device key and rotate the challenge.
        session.state = SessionState::Bound;
        session.public_key = proof.jwk.as_ref().map(serde_json::Value::to_string);
        session.algorithm = Some(proof.algorithm.clone());
        session.challenge = Some(generate_challenge());
        self.apply_ttl(&mut session);
        self.store.update(&session)?;

        Ok(ManagerResponse {
            status_code: 200,
            set_cookie: Some(self.build_cookie(&session.id, self.config.cookie_ttl_seconds)),
            registration_header: None,
            challenge_header: Some(header::challenge_header(
                session.challenge.as_deref().unwrap_or_default(),
                &session.id,
            )),
            body: Some(self.instruction_body(&session)?),
        })
    }

    /// Handle a DBSC refresh request.
    ///
    /// `session_id` comes from the `Sec-Secure-Session-Id` header or cookie;
    /// `session_response_header` from the `Secure-Session-Response` header
    /// (`None` for the optimistic first request).
    pub fn refresh(
        &self,
        session_id: &str,
        session_response_header: Option<&str>,
    ) -> Result<ManagerResponse> {
        let mut session = match self.store.get(session_id)? {
            Some(s) => s,
            None => return Ok(ManagerResponse::with_status(401)),
        };
        if session.state != SessionState::Bound {
            return Ok(ManagerResponse::with_status(400));
        }

        let jwt_str = match session_response_header.and_then(header::parse_session_response) {
            Some(j) => j,
            None => return Ok(ManagerResponse::challenge_failure(&session)),
        };

        let registered_jwk = session
            .public_key
            .as_deref()
            .ok_or_else(|| Error::Store("bound session without public key".into()))?;
        let proof = match jwt::verify_refresh(&jwt_str, registered_jwk) {
            Ok(p) => p,
            Err(_) => return Ok(ManagerResponse::challenge_failure(&session)),
        };
        if session.challenge.as_deref() != Some(proof.challenge.as_str()) {
            return Ok(ManagerResponse::challenge_failure(&session));
        }

        // Rotate the challenge and refresh the TTL.
        session.challenge = Some(generate_challenge());
        self.apply_ttl(&mut session);
        self.store.update(&session)?;

        Ok(ManagerResponse {
            status_code: 200,
            set_cookie: None,
            registration_header: None,
            challenge_header: Some(header::challenge_header(
                session.challenge.as_deref().unwrap_or_default(),
                &session.id,
            )),
            body: Some(self.instruction_body(&session)?),
        })
    }

    /// Close a session (spec 9.6): remove it from the store, respond with a
    /// `{"continue": false}` instruction and an expired session cookie.
    pub fn close(&self, session_id: &str) -> Result<ManagerResponse> {
        self.store.delete(session_id)?;
        Ok(ManagerResponse {
            status_code: 200,
            set_cookie: Some(self.build_cookie("", 0)),
            registration_header: None,
            challenge_header: None,
            body: Some(SessionInstruction::terminate().to_json_string()?),
        })
    }

    /// Fetch a session by cookie value (expired sessions return `None`).
    pub fn get_session(&self, cookie_session_id: &str) -> Result<Option<Session>> {
        self.store.get(cookie_session_id)
    }
}

/// Generate a random 32-byte hex challenge.
pub fn generate_challenge() -> String {
    use rand::Rng;
    use std::fmt::Write;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::tests_helpers;
    use crate::store::MemoryStore;

    fn setup() -> Manager {
        Manager::new(
            Arc::new(MemoryStore::new()),
            ManagerConfig {
                authorization: Some("auth-code".into()),
                session_ttl_seconds: Some(600),
                ..Default::default()
            },
        )
    }

    #[test]
    fn full_flow() {
        let mgr = setup();

        // initiate
        let (session, resp) = mgr.initiate("alice").unwrap();
        assert_eq!(resp.status_code, 200);
        let cookie = resp.set_cookie.unwrap();
        assert!(cookie.starts_with("session_id="));
        assert!(cookie.contains("HttpOnly"));
        let reg = resp.registration_header.unwrap();
        assert!(reg.starts_with("(ES256 RS256)"));
        assert!(reg.contains("path=\"/dbsc/register\""));
        assert!(reg.contains("authorization=\"auth-code\""));

        // register without proof -> 403 + challenge with id
        let r = mgr.register(&session.id, None).unwrap();
        assert_eq!(r.status_code, 403);
        assert!(r.challenge_header.unwrap().contains(";id=\""));

        // register with invalid proof (wrong challenge) -> 403
        let (key, jwk) = tests_helpers::make_es256_key();
        let bad = tests_helpers::sign_es256(&key, Some(&jwk), "dbsc+jwt", "wrong", Some("auth-code"));
        let hdr = header::session_response_header(&bad);
        let r = mgr.register(&session.id, Some(&hdr)).unwrap();
        assert_eq!(r.status_code, 403);

        // register with valid proof -> 200, session bound
        let current = mgr.get_session(&session.id).unwrap().unwrap();
        let challenge = current.challenge.clone().unwrap();
        let good = tests_helpers::sign_es256(&key, Some(&jwk), "dbsc+jwt", &challenge, Some("auth-code"));
        let hdr = header::session_response_header(&good);
        let r = mgr.register(&session.id, Some(&hdr)).unwrap();
        assert_eq!(r.status_code, 200);
        assert!(r.challenge_header.is_some());
        let body = r.body.unwrap();
        assert!(body.contains("\"session_identifier\""));

        let bound = mgr.get_session(&session.id).unwrap().unwrap();
        assert_eq!(bound.state, SessionState::Bound);
        assert_eq!(bound.public_key, Some(jwk.to_string()));
        assert_eq!(bound.algorithm.as_deref(), Some("ES256"));
        assert_ne!(bound.challenge.as_deref(), Some(challenge.as_str()));
        assert_eq!(bound.expires_at, Some(bound.created_at + 600));

        // refresh without proof -> 403 + challenge
        let r = mgr.refresh(&session.id, None).unwrap();
        assert_eq!(r.status_code, 403);
        assert!(r.challenge_header.unwrap().contains(&format!("id=\"{}\"", session.id)));

        // refresh with valid proof -> 200
        let current = mgr.get_session(&session.id).unwrap().unwrap();
        let proof = tests_helpers::sign_es256(
            &key,
            None,
            "dbsc+jwt",
            current.challenge.as_deref().unwrap(),
            None,
        );
        let hdr = header::session_response_header(&proof);
        let r = mgr.refresh(&session.id, Some(&hdr)).unwrap();
        assert_eq!(r.status_code, 200);
        assert!(r.body.unwrap().contains("\"continue\":true"));

        // refresh again with the old (rotated-out) challenge -> 403
        let hdr = header::session_response_header(&proof);
        let r = mgr.refresh(&session.id, Some(&hdr)).unwrap();
        assert_eq!(r.status_code, 403);

        // refresh on active session -> 400
        let (s2, _) = mgr.initiate("bob").unwrap();
        assert_eq!(mgr.refresh(&s2.id, None).unwrap().status_code, 400);

        // unknown session ids
        assert_eq!(mgr.register("nope", None).unwrap().status_code, 401);
        assert_eq!(mgr.refresh("nope", None).unwrap().status_code, 401);

        // close -> 200, {"continue":false}, expired cookie, session gone
        let r = mgr.close(&session.id).unwrap();
        assert_eq!(r.status_code, 200);
        assert_eq!(r.body.as_deref(), Some("{\"continue\":false}"));
        assert!(r.set_cookie.unwrap().contains("Max-Age=0"));
        assert!(mgr.get_session(&session.id).unwrap().is_none());
    }

    #[test]
    fn register_wrong_authorization_rejected() {
        let mgr = setup();
        let (session, _) = mgr.initiate("alice").unwrap();
        let (key, jwk) = tests_helpers::make_es256_key();
        let challenge = mgr
            .get_session(&session.id)
            .unwrap()
            .unwrap()
            .challenge
            .unwrap();
        let token =
            tests_helpers::sign_es256(&key, Some(&jwk), "dbsc+jwt", &challenge, Some("other"));
        let hdr = header::session_response_header(&token);
        assert_eq!(mgr.register(&session.id, Some(&hdr)).unwrap().status_code, 403);
    }

    #[test]
    fn challenge_is_64_hex_chars() {
        let c = generate_challenge();
        assert_eq!(c.len(), 64);
        assert!(c.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn expired_session_is_gone() {
        let store = Arc::new(MemoryStore::new());
        let mgr = Manager::new(
            store.clone(),
            ManagerConfig {
                session_ttl_seconds: Some(60),
                ..Default::default()
            },
        );
        let (session, _) = mgr.initiate("alice").unwrap();
        assert!(mgr.get_session(&session.id).unwrap().is_some());

        // Force the stored session into the past.
        let mut expired = store.get(&session.id).unwrap().unwrap();
        expired.expires_at = Some(crate::session::now_unix() - 1);
        store.update(&expired).unwrap();

        assert!(mgr.get_session(&session.id).unwrap().is_none());
        // Protocol endpoints treat it as unknown.
        assert_eq!(mgr.register(&session.id, None).unwrap().status_code, 401);
        assert_eq!(mgr.refresh(&session.id, None).unwrap().status_code, 401);
    }

    #[test]
    fn cookie_domain_included_when_configured() {
        let mgr = Manager::new(
            Arc::new(MemoryStore::new()),
            ManagerConfig {
                cookie_domain: Some("example.com".into()),
                same_site: "Strict".into(),
                ..Default::default()
            },
        );
        let (_, resp) = mgr.initiate("alice").unwrap();
        let cookie = resp.set_cookie.unwrap();
        assert!(cookie.contains("; Domain=example.com"));
        assert!(cookie.contains("; SameSite=Strict"));
        assert!(cookie.contains("; Secure"));

        // Without a domain, no Domain attribute is emitted.
        let mgr2 = Manager::new(Arc::new(MemoryStore::new()), ManagerConfig::default());
        let (_, resp2) = mgr2.initiate("alice").unwrap();
        assert!(!resp2.set_cookie.unwrap().contains("Domain="));
    }
}
