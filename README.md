# dbsc

Server-side **DBSC (Device Bound Session Credentials)** implementation in
Rust, based on the latest W3C DBSC draft. It is a memory-safe, dependency-minimal,
**framework-agnostic** port of the C library
[opendbsc](https://github.com/OpenDBSC/opendbsc) - it
implements the same protocol core (registration / refresh / close flows,
structured-field headers, session instructions, proof-JWT verification)
without any web-framework coupling. Mapping `ManagerResponse` onto actual
HTTP responses is left to the caller.

`#![forbid(unsafe_code)]` is set crate-wide.

## Features

- RFC 9651 structured-field serialization/parsing for
  `Secure-Session-Registration`, `Secure-Session-Challenge`,
  `Secure-Session-Response`, `Sec-Secure-Session-Id`, and
  `Secure-Session-Skipped` (`header` module).
- Session instruction JSON model (spec 9.6-9.9), including the
  `{"continue": false}` termination instruction (`instruction` module).
- DBSC proof-JWT decoding and signature verification (spec 9.10):
  - `ES256` (P-256 + SHA-256, raw `R||S` signatures), `RS256`
    (RSASSA-PKCS1-v1_5 + SHA-256), and `none`.
  - Registration rules: `jwk` header claim required for ES256/RS256,
    forbidden for `none`; signature verified against the embedded JWK.
  - Refresh rules: embedded `jwk` rejected, `none` rejected, signature
    verified against the registered JWK; `typ` must be exactly `dbsc+jwt`.
- Session model with expiry handling and UUID v4 identifiers
  (`session` module).
- `SessionStore` trait with a thread-safe in-memory implementation
  (`MemoryStore`) (`store` module).
- High-level `Manager` orchestrating the full protocol flow: `initiate`,
  `register`, `refresh`, `close`, challenge rotation, cookie building
  (`manager` module).

## Usage

```rust
use std::sync::Arc;
use dbsc::{Manager, ManagerConfig, MemoryStore, Result};

fn main() -> Result<()> {
let manager = Manager::new(
    Arc::new(MemoryStore::new()),
    ManagerConfig {
        secure: true,
        session_ttl_seconds: Some(3600),
        authorization: Some("login-auth-code".into()),
        ..Default::default()
    },
);

// 1. After a successful login:
let (session, resp) = manager.initiate("user-123")?;
// resp.set_cookie          -> Set-Cookie header
// resp.registration_header -> Secure-Session-Registration header

// 2. Registration request to `register_path` (default /dbsc/register):
//    The cookie carries the session id; the browser answers with a
//    Secure-Session-Response proof JWT.
let resp = manager.register(&session.id, Some("\"eyJ...\""))?;
match resp.status_code {
    200 => { /* session is now device-bound; body = session instruction */ }
    403 => { /* challenge_header carries the challenge to retry with */ }
    _   => { /* 400/401 errors */ }
}

// 3. Refresh request to `refresh_path` (default /dbsc/refresh):
let resp = manager.refresh(&session.id, Some("\"eyJ...\""))?;
// None for the response header implements the optimistic first request,
// which is answered with 403 + a Secure-Session-Challenge.

// 4. Close the session:
let resp = manager.close(&session.id)?;
// resp.body == Some("{\"continue\":false}"), cookie expired via Max-Age=0.
Ok(())
}
```

## Extending the store

Implement `dbsc::SessionStore` for your backend (database, Redis, ...) and
pass it to `Manager::new` as `Arc<dyn SessionStore>`:

```rust
use dbsc::{Error, Result, Session, SessionStore};

struct MyStore { /* connection pool, ... */ }

impl SessionStore for MyStore {
    fn create(&self, session: &Session) -> Result<()> { /* ... */ }
    fn get(&self, id: &str) -> Result<Option<Session>> {
        // Return None for expired sessions (see Session::is_expired).
        Ok(None)
    }
    fn update(&self, session: &Session) -> Result<()> { /* ... */ }
    fn delete(&self, id: &str) -> Result<()> {
        // Must succeed even when the id does not exist.
        Ok(())
    }
    fn get_by_user_id(&self, user_id: &str) -> Result<Vec<Session>> { /* ... */ }
    fn delete_by_user_id(&self, user_id: &str) -> Result<()> { /* ... */ }
}
```

Sessions are cloned in and out of the store, mirroring the deep-copy
semantics of the C implementation, so implementations never share mutable
state with the caller.

## Dependencies

Kept minimal on purpose; no async runtime, no HTTP framework, no `thiserror`:

| Crate        | Purpose                                   |
|--------------|-------------------------------------------|
| `serde`      | Instruction/JWT JSON models               |
| `serde_json` | JSON (de)serialization                    |
| `base64`     | base64url (padding-optional)              |
| `p256`       | ES256 verification (and test signing)     |
| `rsa`        | RS256 verification                        |
| `sha2`       | SHA-256 for RS256                         |
| `uuid` (v4)  | Session id generation                     |
| `rand`       | Random 32-byte challenges                 |

The `Error` type implements `std::error::Error` by hand instead of pulling
in `thiserror`.

## Relationship to opendbsc

This crate is a Rust port of the server-side core of
[opendbsc](https://github.com/yjlee/opendbsc), a C implementation built on
mongoose/hiredis/cJSON/OpenSSL. The Rust version replaces:

- C string/header serialization -> `header` module (RFC 9651),
- OpenSSL ECDSA/RSA verification -> `p256` / `rsa` crates,
- SQLite/Redis store backends -> the `SessionStore` trait + `MemoryStore`,
- mongoose HTTP wrapper -> intentionally omitted (framework-agnostic core).

## Examples

```sh
cargo run --example demo
```

`examples/demo.rs` simulates a full DBSC exchange with no network and no web
framework: a "browser" struct holding an ES256 key pair and a "server"
running `dbsc::Manager`. It walks through, printing every HTTP header and
body at each step:

1. login -> `initiate` (session cookie + `Secure-Session-Registration`),
2. registration: first a proof-less request (403 + challenge), then a
   properly signed proof JWT with an embedded JWK (200 + instruction),
3. refresh after cookie expiry: optimistic request (403 + challenge), then a
   refresh proof signed with the registered key (200 + rotated challenge),
4. `close` (200 + `{"continue": false}` + cookie expired via `Max-Age=0`).

## Tests

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

`Cargo.lock` is committed (not gitignored) to keep builds reproducible.

Covers header round-trips, skipped-header parsing, instruction JSON shape,
JWT verification (valid/invalid/tampered proofs, typ and jwk-claim rules),
and the full `initiate -> register -> refresh -> close` manager flow.
