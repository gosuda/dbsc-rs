//! Error type for the dbsc crate.

use std::fmt;

/// Errors produced by the dbsc crate.
#[derive(Debug)]
pub enum Error {
    /// A JWT was malformed (bad structure, base64, or JSON).
    MalformedJwt(String),
    /// The JWT `typ` header was not exactly `dbsc+jwt`.
    InvalidTyp,
    /// The JWT `alg` is not supported.
    UnsupportedAlgorithm(String),
    /// The JWT carried (or was missing) a `jwk` header claim contrary to the
    /// rules of the flow being verified.
    InvalidJwkClaim(String),
    /// The JWK could not be parsed into a usable public key.
    InvalidKey(String),
    /// The signature did not verify.
    InvalidSignature,
    /// Base64 decoding failed.
    Base64(String),
    /// JSON (de)serialization failed.
    Json(String),
    /// The session store backend failed.
    Store(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MalformedJwt(m) => write!(f, "malformed JWT: {m}"),
            Error::InvalidTyp => write!(f, "invalid typ header, expected \"dbsc+jwt\""),
            Error::UnsupportedAlgorithm(a) => write!(f, "unsupported algorithm: {a}"),
            Error::InvalidJwkClaim(m) => write!(f, "invalid jwk claim: {m}"),
            Error::InvalidKey(m) => write!(f, "invalid key: {m}"),
            Error::InvalidSignature => write!(f, "signature verification failed"),
            Error::Base64(m) => write!(f, "base64 error: {m}"),
            Error::Json(m) => write!(f, "JSON error: {m}"),
            Error::Store(m) => write!(f, "store error: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e.to_string())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Base64(e.to_string())
    }
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, Error>;
