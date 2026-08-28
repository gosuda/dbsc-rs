//! DBSC proof JWT decoding and signature verification (spec 9.10).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// JWT `typ` header value required for DBSC proofs.
pub const DBSC_TYP: &str = "dbsc+jwt";

/// A decoded DBSC proof JWT.
#[derive(Debug, Clone)]
pub struct ProofJwt {
    /// Signing algorithm ("ES256", "RS256", "none").
    pub algorithm: String,
    /// Public key as a JWK JSON value (`None` for `alg = none`).
    pub jwk: Option<Value>,
    /// Challenge value from the `jti` claim.
    pub challenge: String,
    /// Optional authorization value echoed during registration.
    pub authorization: Option<String>,
    /// Raw signature bytes (empty for `alg = none`).
    pub signature: Vec<u8>,
    /// The signed content (`header.payload`), raw bytes.
    pub signing_input: Vec<u8>,
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    typ: Option<String>,
    jwk: Option<Value>,
}

#[derive(Deserialize)]
struct JwtPayload {
    jti: Option<String>,
    authorization: Option<String>,
}

/// Base64url-decode (padding optional).
pub fn base64url_decode(input: &str) -> Result<Vec<u8>> {
    Ok(URL_SAFE_NO_PAD.decode(input.trim_end_matches('='))?)
}

/// Base64url-encode without padding.
pub fn base64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn jwk_field<'a>(jwk: &'a Value, key: &str) -> Result<&'a str> {
    jwk.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidKey(format!("missing JWK field `{key}`")))
}

/// Verify an ES256 signature (raw R||S, RFC 7518) against a P-256 JWK.
fn verify_es256(jwk: &Value, signing_input: &[u8], signature: &[u8]) -> Result<()> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    if jwk_field(jwk, "kty")? != "EC" || jwk_field(jwk, "crv")? != "P-256" {
        return Err(Error::InvalidKey("expected EC/P-256 JWK".into()));
    }
    let x = base64url_decode(jwk_field(jwk, "x")?)?;
    let y = base64url_decode(jwk_field(jwk, "y")?)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(Error::InvalidKey("P-256 coordinates must be 32 bytes".into()));
    }
    // Uncompressed SEC1 point: 0x04 || X || Y.
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let key = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| Error::InvalidKey(e.to_string()))?;
    let sig = Signature::from_slice(signature).map_err(|_| Error::InvalidSignature)?;
    key.verify(signing_input, &sig)
        .map_err(|_| Error::InvalidSignature)
}

/// Verify an RS256 signature against an RSA JWK.
fn verify_rs256(jwk: &Value, signing_input: &[u8], signature: &[u8]) -> Result<()> {
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::BigUint;

    if jwk_field(jwk, "kty")? != "RSA" {
        return Err(Error::InvalidKey("expected RSA JWK".into()));
    }
    let n = BigUint::from_bytes_be(&base64url_decode(jwk_field(jwk, "n")?)?);
    let e = BigUint::from_bytes_be(&base64url_decode(jwk_field(jwk, "e")?)?);
    let key = rsa::RsaPublicKey::new(n, e).map_err(|e| Error::InvalidKey(e.to_string()))?;
    let digest = Sha256::digest(signing_input);
    key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, signature)
        .map_err(|_| Error::InvalidSignature)
}

/// Verify a signature according to `alg`. `alg = none` always succeeds.
fn verify_signature(alg: &str, jwk: &Value, signing_input: &[u8], signature: &[u8]) -> Result<()> {
    match alg {
        "ES256" => verify_es256(jwk, signing_input, signature),
        "RS256" => verify_rs256(jwk, signing_input, signature),
        "none" => Ok(()),
        other => Err(Error::UnsupportedAlgorithm(other.to_string())),
    }
}

/// Decode a DBSC proof JWT without verifying its signature.
pub fn decode(token: &str) -> Result<ProofJwt> {
    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or_else(|| Error::MalformedJwt("empty token".into()))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| Error::MalformedJwt("missing payload".into()))?;
    let signature_b64 = parts
        .next()
        .ok_or_else(|| Error::MalformedJwt("missing signature".into()))?;
    if parts.next().is_some() {
        return Err(Error::MalformedJwt("too many segments".into()));
    }

    let header_json = base64url_decode(header_b64)?;
    let header: JwtHeader = serde_json::from_slice(&header_json)?;
    if header.typ.as_deref() != Some(DBSC_TYP) {
        return Err(Error::InvalidTyp);
    }

    let payload_json = base64url_decode(payload_b64)?;
    let payload: JwtPayload = serde_json::from_slice(&payload_json)?;

    let signed_len = token.len() - signature_b64.len() - 1;
    let signing_input = token.as_bytes()[..signed_len].to_vec();
    let signature = base64url_decode(signature_b64)?;

    Ok(ProofJwt {
        algorithm: header.alg,
        jwk: header.jwk,
        challenge: payload
            .jti
            .ok_or_else(|| Error::MalformedJwt("missing jti claim".into()))?,
        authorization: payload.authorization,
        signature,
        signing_input,
    })
}

/// Decode and verify a registration proof JWT.
///
/// Rules (spec 9.10): for `ES256`/`RS256` the header must carry a `jwk`
/// claim whose key verifies the signature; for `none` a `jwk` claim is
/// forbidden.
pub fn verify_registration(token: &str) -> Result<ProofJwt> {
    let proof = decode(token)?;
    match proof.algorithm.as_str() {
        "none" => {
            if proof.jwk.is_some() {
                return Err(Error::InvalidJwkClaim(
                    "jwk claim forbidden for alg=none".into(),
                ));
            }
        }
        "ES256" | "RS256" => {
            let jwk = proof.jwk.as_ref().ok_or_else(|| {
                Error::InvalidJwkClaim("jwk claim required for registration".into())
            })?;
            verify_signature(&proof.algorithm, jwk, &proof.signing_input, &proof.signature)?;
        }
        other => return Err(Error::UnsupportedAlgorithm(other.to_string())),
    }
    Ok(proof)
}

/// Verify a refresh proof JWT against the registered JWK (JSON string).
///
/// The token must not carry a `jwk` header claim (the key is pinned to the
/// registered value) and `alg = none` is rejected.
pub fn verify_refresh(token: &str, registered_jwk_json: &str) -> Result<ProofJwt> {
    let proof = decode(token)?;
    if proof.jwk.is_some() {
        return Err(Error::InvalidJwkClaim(
            "jwk claim forbidden during refresh".into(),
        ));
    }
    if proof.algorithm == "none" {
        return Err(Error::UnsupportedAlgorithm(
            "alg=none not allowed during refresh".into(),
        ));
    }
    let jwk: Value = serde_json::from_str(registered_jwk_json)?;
    verify_signature(&proof.algorithm, &jwk, &proof.signing_input, &proof.signature)?;
    Ok(proof)
}

#[cfg(test)]
pub(crate) mod tests_helpers {
    use super::base64url_encode;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::elliptic_curve::Generate;
    use serde_json::Value;

    /// Generate an ES256 signing key and its public JWK.
    pub(crate) fn make_es256_key() -> (SigningKey, Value) {
        let key = SigningKey::generate();
        let point = key.verifying_key().to_sec1_point(false);
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64url_encode(point.x().unwrap()),
            "y": base64url_encode(point.y().unwrap()),
        });
        (key, jwk)
    }

    /// Build and sign an ES256 JWT.
    pub(crate) fn sign_es256(
        key: &SigningKey,
        jwk: Option<&Value>,
        typ: &str,
        jti: &str,
        authorization: Option<&str>,
    ) -> String {
        let mut header = serde_json::json!({"alg": "ES256", "typ": typ});
        if let Some(jwk) = jwk {
            header["jwk"] = jwk.clone();
        }
        let mut payload = serde_json::json!({"jti": jti});
        if let Some(a) = authorization {
            payload["authorization"] = serde_json::Value::String(a.to_string());
        }
        let input = format!(
            "{}.{}",
            base64url_encode(header.to_string().as_bytes()),
            base64url_encode(payload.to_string().as_bytes())
        );
        let sig: Signature = key.sign(input.as_bytes());
        format!("{}.{}", input, base64url_encode(&sig.to_bytes()))
    }

    /// Generate a 2048-bit RSA signing key and its public JWK.
    pub(crate) fn make_rs256_key() -> (rsa::RsaPrivateKey, Value) {
        use rsa::traits::PublicKeyParts;
        let mut rng = rsa::rand_core::OsRng;
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": base64url_encode(&key.n().to_bytes_be()),
            "e": base64url_encode(&key.e().to_bytes_be()),
        });
        (key, jwk)
    }

    /// Build and sign an RS256 JWT.
    pub(crate) fn sign_rs256(
        key: &rsa::RsaPrivateKey,
        jwk: Option<&Value>,
        typ: &str,
        jti: &str,
    ) -> String {
        use rsa::pkcs1v15::Pkcs1v15Sign;
        use sha2::{Digest, Sha256};

        let mut header = serde_json::json!({"alg": "RS256", "typ": typ});
        if let Some(jwk) = jwk {
            header["jwk"] = jwk.clone();
        }
        let payload = serde_json::json!({"jti": jti});
        let input = format!(
            "{}.{}",
            base64url_encode(header.to_string().as_bytes()),
            base64url_encode(payload.to_string().as_bytes())
        );
        let digest = Sha256::digest(input.as_bytes());
        let sig = key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .unwrap();
        format!("{}.{}", input, base64url_encode(&sig))
    }
}

#[cfg(test)]
mod tests {
    use super::tests_helpers::{make_es256_key, make_rs256_key, sign_es256, sign_rs256};
    use super::*;

    #[test]
    fn decode_typ_enforced() {
        let (key, jwk) = make_es256_key();
        let good = sign_es256(&key, Some(&jwk), "dbsc+jwt", "c1", None);
        assert!(decode(&good).is_ok());
        let bad = sign_es256(&key, Some(&jwk), "JWT", "c1", None);
        assert!(matches!(decode(&bad), Err(Error::InvalidTyp)));
    }

    #[test]
    fn registration_verify_ok() {
        let (key, jwk) = make_es256_key();
        let token = sign_es256(&key, Some(&jwk), "dbsc+jwt", "challenge-1", Some("auth"));
        let proof = verify_registration(&token).unwrap();
        assert_eq!(proof.algorithm, "ES256");
        assert_eq!(proof.challenge, "challenge-1");
        assert_eq!(proof.authorization.as_deref(), Some("auth"));
        assert_eq!(proof.jwk.unwrap(), jwk);
    }

    #[test]
    fn registration_wrong_jti_fails() {
        let (key, jwk) = make_es256_key();
        // Token signed over a different jti than expected by the caller is
        // caught by comparing proof.challenge; here verify tampering instead.
        let token = sign_es256(&key, Some(&jwk), "dbsc+jwt", "c1", None);
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        // Tamper with payload jti (invalidates signature).
        parts[1] = base64url_encode(br#"{"jti":"c2"}"#);
        let tampered = parts.join(".");
        assert!(matches!(
            verify_registration(&tampered),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn registration_none_alg_rules() {
        let header = base64url_encode(br#"{"alg":"none","typ":"dbsc+jwt"}"#);
        let payload = base64url_encode(br#"{"jti":"c1"}"#);
        let ok = format!("{header}.{payload}.");
        assert_eq!(verify_registration(&ok).unwrap().algorithm, "none");
        let header_with_jwk = base64url_encode(
            br#"{"alg":"none","typ":"dbsc+jwt","jwk":{"kty":"EC","crv":"P-256","x":"a","y":"b"}}"#,
        );
        let bad = format!("{header_with_jwk}.{payload}.");
        assert!(matches!(
            verify_registration(&bad),
            Err(Error::InvalidJwkClaim(_))
        ));
    }

    #[test]
    fn refresh_rejects_embedded_jwk() {
        let (key, jwk) = make_es256_key();
        let token = sign_es256(&key, Some(&jwk), "dbsc+jwt", "c1", None);
        assert!(matches!(
            verify_refresh(&token, &jwk.to_string()),
            Err(Error::InvalidJwkClaim(_))
        ));
    }

    #[test]
    fn refresh_ok_and_wrong_key() {
        let (key, jwk) = make_es256_key();
        let token = sign_es256(&key, None, "dbsc+jwt", "c1", None);
        let proof = verify_refresh(&token, &jwk.to_string()).unwrap();
        assert_eq!(proof.challenge, "c1");

        let (_, other_jwk) = make_es256_key();
        assert!(matches!(
            verify_refresh(&token, &other_jwk.to_string()),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn refresh_rejects_none_alg() {
        let header = base64url_encode(br#"{"alg":"none","typ":"dbsc+jwt"}"#);
        let payload = base64url_encode(br#"{"jti":"c1"}"#);
        let token = format!("{header}.{payload}.");
        let (_, jwk) = make_es256_key();
        assert!(matches!(
            verify_refresh(&token, &jwk.to_string()),
            Err(Error::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn base64url_roundtrip() {
        let data = b"hello, dbsc!";
        assert_eq!(base64url_decode(&base64url_encode(data)).unwrap(), data);
    }

    #[test]
    fn rs256_registration_and_refresh_ok() {
        let (key, jwk) = make_rs256_key();
        let token = sign_rs256(&key, Some(&jwk), "dbsc+jwt", "rsa-challenge");
        let proof = verify_registration(&token).unwrap();
        assert_eq!(proof.algorithm, "RS256");
        assert_eq!(proof.challenge, "rsa-challenge");

        // Refresh: no embedded jwk, verify against the registered JWK.
        let refresh = sign_rs256(&key, None, "dbsc+jwt", "rsa-challenge-2");
        let proof = verify_refresh(&refresh, &jwk.to_string()).unwrap();
        assert_eq!(proof.challenge, "rsa-challenge-2");
    }

    #[test]
    fn rs256_wrong_key_and_missing_jwk_fail() {
        let (key, jwk) = make_rs256_key();

        // Registration requires the jwk header claim for RS256.
        let no_jwk = sign_rs256(&key, None, "dbsc+jwt", "c1");
        assert!(matches!(
            verify_registration(&no_jwk),
            Err(Error::InvalidJwkClaim(_))
        ));

        // Refresh against a different RSA key must fail.
        let (_, other_jwk) = make_rs256_key();
        let token = sign_rs256(&key, None, "dbsc+jwt", "c1");
        assert!(matches!(
            verify_refresh(&token, &other_jwk.to_string()),
            Err(Error::InvalidSignature)
        ));

        // Refresh with embedded jwk is rejected even for RS256.
        let embedded = sign_rs256(&key, Some(&jwk), "dbsc+jwt", "c1");
        assert!(matches!(
            verify_refresh(&embedded, &jwk.to_string()),
            Err(Error::InvalidJwkClaim(_))
        ));
    }
}
