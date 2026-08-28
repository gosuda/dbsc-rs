//! DBSC session model.

use serde::{Deserialize, Serialize};

/// Lifecycle state of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Created by the server, not yet bound to a device key.
    Active,
    /// Bound to a device public key after successful registration.
    Bound,
}

/// A DBSC session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier (UUID v4).
    pub id: String,
    /// Owning user identifier.
    pub user_id: String,
    /// Lifecycle state.
    pub state: SessionState,
    /// Registered device public key as a JWK JSON string (set when bound).
    pub public_key: Option<String>,
    /// Algorithm of the registered key ("ES256" or "RS256").
    pub algorithm: Option<String>,
    /// Current challenge the client must sign in its next proof JWT.
    pub challenge: Option<String>,
    /// Expiry as a unix timestamp in seconds (`None` = never expires).
    pub expires_at: Option<i64>,
    /// Creation time as a unix timestamp in seconds.
    pub created_at: i64,
}

impl Session {
    /// Create a new active session for `user_id`.
    pub fn new(user_id: impl Into<String>) -> Self {
        Session {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.into(),
            state: SessionState::Active,
            public_key: None,
            algorithm: None,
            challenge: None,
            expires_at: None,
            created_at: now_unix(),
        }
    }

    /// Whether the session is expired at unix time `now`.
    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|exp| now >= exp)
    }
}

/// Current unix time in seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry() {
        let mut s = Session::new("user");
        assert!(!s.is_expired(now_unix()));
        s.expires_at = Some(100);
        assert!(s.is_expired(100));
        assert!(!s.is_expired(99));
    }

    #[test]
    fn expiry_boundary() {
        // expires_at == now counts as expired; None never expires.
        let mut s = Session::new("user");
        assert!(!s.is_expired(i64::MAX));
        let now = now_unix();
        s.expires_at = Some(now);
        assert!(s.is_expired(now));
        s.expires_at = Some(now - 1);
        assert!(s.is_expired(now));
        s.expires_at = Some(now + 1);
        assert!(!s.is_expired(now));
    }
}
