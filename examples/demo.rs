//! DBSC demo: a simulated end-to-end protocol run.
//!
//! DBSC (Device Bound Session Credentials) is a W3C draft that binds a web
//! session to a cryptographic key held by the browser. After login, the
//! server asks the browser to register a fresh public key; from then on, the
//! browser proves possession of the private key with a signed JWT on every
//! session refresh, so stolen cookies alone cannot hijack the session.
//!
//! This example simulates both sides with plain structs (no network, no web
//! framework): a "server" running dbsc::Manager and a "browser" holding an
//! ES256 key pair. Run it with: cargo run --example demo

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use dbsc::{Manager, ManagerConfig, ManagerResponse, MemoryStore, Session};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::elliptic_curve::Generate;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Browser-side helpers (normally implemented by the user agent itself).
// ---------------------------------------------------------------------------

/// The simulated browser: holds the device key pair and signs proof JWTs.
struct Browser {
    key: Option<SigningKey>,
}

impl Browser {
    fn new() -> Self {
        Browser { key: None }
    }

    /// Generate the device key pair during registration.
    fn generate_key(&mut self) {
        self.key = Some(SigningKey::generate());
    }

    /// The public key as a JWK JSON value (sent only at registration).
    fn public_jwk(&self) -> serde_json::Value {
        let point = self.key.as_ref().unwrap().verifying_key().to_sec1_point(false);
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        })
    }

    /// Build and sign a DBSC proof JWT for `challenge`.
    /// `authorization` echoes the value from the registration header and is
    /// only sent (and required) during registration.
    fn sign_proof(&self, challenge: &str, include_jwk: bool, authorization: Option<&str>) -> String {
        let mut header = serde_json::json!({"alg": "ES256", "typ": "dbsc+jwt"});
        if include_jwk {
            header["jwk"] = self.public_jwk();
        }
        let mut payload = serde_json::json!({"jti": challenge});
        if let Some(a) = authorization {
            payload["authorization"] = a.into();
        }
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
            URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes())
        );
        let sig: Signature = self.key.as_ref().unwrap().sign(input.as_bytes());
        format!("{}.{}", input, URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }
}

// ---------------------------------------------------------------------------
// Tiny print helpers to make the exchange readable.
// ---------------------------------------------------------------------------

fn show_response(resp: &ManagerResponse) {
    println!("  HTTP {}", resp.status_code);
    if let Some(c) = &resp.set_cookie {
        println!("  Set-Cookie: {c}");
    }
    if let Some(h) = &resp.registration_header {
        println!("  Secure-Session-Registration: {h}");
    }
    if let Some(h) = &resp.challenge_header {
        println!("  Secure-Session-Challenge: {h}");
    }
    if let Some(b) = &resp.body {
        println!("  Body: {b}");
    }
}

fn step(n: usize, title: &str) {
    println!("\n=== Step {n}: {title} ===");
}

fn main() -> dbsc::Result<()> {
    let mut browser = Browser::new();
    let manager = Manager::new(
        Arc::new(MemoryStore::new()),
        ManagerConfig {
            cookie_domain: Some("example.com".into()),
            session_ttl_seconds: Some(3600),
            authorization: Some("login-auth-code".into()),
            ..Default::default()
        },
    );

    // -- Login: the user authenticated, the server starts a DBSC session. ---
    step(1, "Login succeeded -> server initiates a DBSC session");
    let (session, resp) = manager.initiate("alice")?;
    println!("POST /login");
    show_response(&resp);
    println!("  (session id: {}, state: {:?})", session.id, session.state);

    // -- Registration: the browser signs the challenge with a fresh key. ----
    step(2, "Browser registers its device key");
    browser.generate_key();
    println!("  (browser generated an ES256 key pair, JWK: {})", browser.public_jwk());

    // First attempt: no proof JWT at all -> 403 with a challenge.
    println!("POST /dbsc/register  (Cookie: session_id={})", session.id);
    println!("  (browser forgot the Secure-Session-Response header)");
    let resp = manager.register(&session.id, None)?;
    show_response(&resp);

    // Second attempt: browser signs the challenge, embedding its JWK.
    let stored = manager.get_session(&session.id)?.unwrap();
    let challenge = stored.challenge.clone().unwrap();
    let proof = browser.sign_proof(&challenge, true, Some("login-auth-code"));
    println!("POST /dbsc/register  (Cookie: session_id={})", session.id);
    println!("  Secure-Session-Response: {}", dbsc::header::session_response_header(&proof));
    let resp = manager.register(&session.id, Some(&dbsc::header::session_response_header(&proof)))?;
    show_response(&resp);
    let bound: Session = manager.get_session(&session.id)?.unwrap();
    println!("  (session is now {:?}, bound to the device key)", bound.state);

    // -- Refresh: short-lived cookies expired, browser proves possession. ---
    step(3, "Session cookie expired -> browser refreshes");
    println!("POST /dbsc/refresh  (Sec-Secure-Session-Id: \"{}\")", session.id);
    let resp = manager.refresh(&session.id, None)?;
    println!("  (optimistic refresh, no proof yet)");
    show_response(&resp);

    let challenge = manager.get_session(&session.id)?.unwrap().challenge.unwrap();
    let proof = browser.sign_proof(&challenge, false, None); // no JWK during refresh
    println!("POST /dbsc/refresh  (Sec-Secure-Session-Id: \"{}\")", session.id);
    println!("  Secure-Session-Response: {}", dbsc::header::session_response_header(&proof));
    let resp = manager.refresh(&session.id, Some(&dbsc::header::session_response_header(&proof)))?;
    show_response(&resp);

    // -- Close: the server ends the session. --------------------------------
    step(4, "Server closes the session");
    println!("POST /dbsc/close  (Sec-Secure-Session-Id: \"{}\")", session.id);
    let resp = manager.close(&session.id)?;
    show_response(&resp);
    println!("  (session deleted: {})", manager.get_session(&session.id)?.is_none());

    println!("\nDone. The session was cryptographically bound to the device key.");
    Ok(())
}
