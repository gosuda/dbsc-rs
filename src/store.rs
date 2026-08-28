//! Session storage: a pluggable trait plus an in-memory implementation.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::session::{now_unix, Session};

/// Backend interface for session persistence.
///
/// Implementations must be thread-safe (`Send + Sync`). Sessions are cloned
/// in and out, mirroring the deep-copy semantics of the C implementation.
pub trait SessionStore: Send + Sync {
    /// Persist a new session.
    fn create(&self, session: &Session) -> Result<()>;
    /// Fetch a session by id. Expired sessions are returned as `None`.
    fn get(&self, id: &str) -> Result<Option<Session>>;
    /// Replace an existing session.
    fn update(&self, session: &Session) -> Result<()>;
    /// Delete a session. Succeeds even if the id does not exist.
    fn delete(&self, id: &str) -> Result<()>;
    /// All sessions owned by a user.
    fn get_by_user_id(&self, user_id: &str) -> Result<Vec<Session>>;
    /// Delete all sessions owned by a user.
    fn delete_by_user_id(&self, user_id: &str) -> Result<()>;
}

/// In-memory `SessionStore` backed by a `Mutex<HashMap>`.
///
/// Suitable for tests, development, and single-process deployments.
#[derive(Debug, Default)]
pub struct MemoryStore {
    sessions: Mutex<HashMap<String, Session>>,
}

impl MemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionStore for MemoryStore {
    fn create(&self, session: &Session) -> Result<()> {
        let mut map = self
            .sessions
            .lock()
            .map_err(|e| Error::Store(e.to_string()))?;
        map.insert(session.id.clone(), session.clone());
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Option<Session>> {
        let map = self
            .sessions
            .lock()
            .map_err(|e| Error::Store(e.to_string()))?;
        match map.get(id) {
            Some(s) if !s.is_expired(now_unix()) => Ok(Some(s.clone())),
            _ => Ok(None),
        }
    }

    fn update(&self, session: &Session) -> Result<()> {
        let mut map = self
            .sessions
            .lock()
            .map_err(|e| Error::Store(e.to_string()))?;
        map.insert(session.id.clone(), session.clone());
        Ok(())
    }

    fn delete(&self, id: &str) -> Result<()> {
        let mut map = self
            .sessions
            .lock()
            .map_err(|e| Error::Store(e.to_string()))?;
        map.remove(id);
        Ok(())
    }

    fn get_by_user_id(&self, user_id: &str) -> Result<Vec<Session>> {
        let map = self
            .sessions
            .lock()
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(map
            .values()
            .filter(|s| s.user_id == user_id && !s.is_expired(now_unix()))
            .cloned()
            .collect())
    }

    fn delete_by_user_id(&self, user_id: &str) -> Result<()> {
        let mut map = self
            .sessions
            .lock()
            .map_err(|e| Error::Store(e.to_string()))?;
        map.retain(|_, s| s.user_id != user_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crud_and_user_queries() {
        let store = MemoryStore::new();
        let mut s1 = Session::new("alice");
        s1.id = "s1".into();
        let mut s2 = Session::new("alice");
        s2.id = "s2".into();
        let mut s3 = Session::new("bob");
        s3.id = "s3".into();

        store.create(&s1).unwrap();
        store.create(&s2).unwrap();
        store.create(&s3).unwrap();

        assert_eq!(store.get("s1").unwrap().unwrap().user_id, "alice");
        assert_eq!(store.get("missing").unwrap(), None);
        assert_eq!(store.get_by_user_id("alice").unwrap().len(), 2);

        s1.user_id = "carol".into();
        store.update(&s1).unwrap();
        assert_eq!(store.get_by_user_id("alice").unwrap().len(), 1);

        store.delete("s3").unwrap();
        store.delete("s3").unwrap(); // idempotent
        assert_eq!(store.get("s3").unwrap(), None);

        store.delete_by_user_id("alice").unwrap();
        assert_eq!(store.get_by_user_id("alice").unwrap().len(), 0);
    }

    #[test]
    fn expired_sessions_hidden() {
        let store = MemoryStore::new();
        let mut s = Session::new("alice");
        s.id = "exp".into();
        s.expires_at = Some(1); // long past
        store.create(&s).unwrap();
        assert_eq!(store.get("exp").unwrap(), None);
    }
}
