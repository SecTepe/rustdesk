// Cookie-based session layer for the admin web console.
//
// The admin logs in through the existing OIDC flow (`src/hbbs_http/account.rs`)
// and POSTs the resulting `access_token` to `/admin/api/session`. This module
// holds the in-memory map from cookie value to an authenticated `AdminSession`,
// along with the HMAC helpers used to validate the public (end-user) endpoints.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use hbb_common::{log, rand::RngCore};
use sha2::{Digest, Sha256};

/// How long an admin cookie remains valid after issuance.
pub const COOKIE_TTL: Duration = Duration::from_secs(12 * 60 * 60);

/// Tolerance for public HMAC timestamps. Requests more than this far in the
/// past (or future) are rejected.
const SIGNATURE_SKEW: i64 = 5 * 60;

#[derive(Debug, Clone)]
pub struct AdminSession {
    pub name: String,
    pub email: Option<String>,
    pub is_admin: bool,
    pub expires_at: Instant,
}

impl AdminSession {
    pub fn expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

#[derive(Default)]
struct SessionMap {
    inner: HashMap<String, AdminSession>,
}

fn sessions() -> &'static Mutex<SessionMap> {
    static SESSIONS: OnceLock<Mutex<SessionMap>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(SessionMap::default()))
}

/// Mint a new cookie value for the given session. Returns the cookie value
/// (hex-encoded 32 random bytes). Expired sessions are purged lazily on every
/// mint.
pub fn issue_cookie(session: AdminSession) -> String {
    let mut bytes = [0u8; 32];
    hbb_common::rand::thread_rng().fill_bytes(&mut bytes);
    let token = hex::encode(bytes);
    let mut map = sessions().lock().unwrap();
    map.inner.retain(|_, s| !s.expired());
    map.inner.insert(token.clone(), session);
    token
}

/// Fetch a session by cookie value, returning `None` if missing or expired.
pub fn lookup_cookie(token: &str) -> Option<AdminSession> {
    let mut map = sessions().lock().unwrap();
    if let Some(s) = map.inner.get(token) {
        if s.expired() {
            map.inner.remove(token);
            return None;
        }
        return Some(s.clone());
    }
    None
}

pub fn revoke_cookie(token: &str) {
    sessions().lock().unwrap().inner.remove(token);
}

// ---------- HMAC for the public endpoints ----------

/// Enrollment secret used to sign `/admin/api/public/*` requests. End-user
/// clients read it from the `admin-enroll-secret` config option; admins set
/// the same value on the server side. An empty secret rejects all public
/// requests — i.e. the feature is off until the admin opts in.
pub fn enrollment_secret() -> String {
    hbb_common::config::Config::get_option("admin-enroll-secret")
}

/// Verify a signature of the form `hex(hmac_sha256(secret, message))`. Uses a
/// constant-time equality check to avoid leaking the secret via timing.
pub fn verify_signature(message: &str, signature_hex: &str, timestamp: i64) -> bool {
    let secret = enrollment_secret();
    if secret.is_empty() {
        return false;
    }
    let now = crate::admin::store::now_secs();
    if (now - timestamp).abs() > SIGNATURE_SKEW {
        log::debug!(
            "admin: rejecting signature, skew = {}s",
            (now - timestamp).abs()
        );
        return false;
    }
    let computed = sign_message(&secret, message);
    constant_time_eq(computed.as_bytes(), signature_hex.as_bytes())
}

/// Compute a hex-encoded HMAC-SHA256 of `message` under `secret`. Exposed so
/// end-user clients can sign their outgoing requests.
pub fn sign_message(secret: &str, message: &str) -> String {
    // Minimal HMAC-SHA256 built on top of sha2::Sha256. We intentionally avoid
    // pulling in another crate just for this.
    const BLOCK_SIZE: usize = 64;
    let mut key = [0u8; BLOCK_SIZE];
    if secret.len() > BLOCK_SIZE {
        let digest = Sha256::digest(secret.as_bytes());
        key[..digest.len()].copy_from_slice(&digest);
    } else {
        key[..secret.len()].copy_from_slice(secret.as_bytes());
    }
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message.as_bytes());
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    hex::encode(outer.finalize())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_mint_and_lookup() {
        let token = issue_cookie(AdminSession {
            name: "admin".into(),
            email: Some("a@example".into()),
            is_admin: true,
            expires_at: Instant::now() + Duration::from_secs(60),
        });
        let got = lookup_cookie(&token).unwrap();
        assert!(got.is_admin);
        revoke_cookie(&token);
        assert!(lookup_cookie(&token).is_none());
    }

    #[test]
    fn expired_cookie_is_rejected() {
        let token = issue_cookie(AdminSession {
            name: "admin".into(),
            email: None,
            is_admin: true,
            expires_at: Instant::now() - Duration::from_secs(1),
        });
        assert!(lookup_cookie(&token).is_none());
    }

    #[test]
    fn hmac_sign_is_stable() {
        let secret = "top-secret";
        let msg = "123456789|uuid|1700000000";
        let a = sign_message(secret, msg);
        let b = sign_message(secret, msg);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // hex of 32 bytes
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
