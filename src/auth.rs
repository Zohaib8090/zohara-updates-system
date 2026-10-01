// Login for the admin site (phase 1 of docs/PLAN.md).
//
// Sign-in goes through GitHub (the GitHub App's "user authorization" flow). The only account let in is the
// numeric GitHub user id in ZOHARA_HUB_ALLOWED_USER_ID: a user id cannot be taken over by renaming an account the
// way a login name can. After sign-in the browser holds one signed cookie. The cookie is
//   base64url(payload) "." base64url(HMAC-SHA256(secret, payload))
// with payload "<user id>|<expires unix time>|<csrf token>", so the server keeps no session state.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub const SESSION_COOKIE: &str = "zhub_session";
pub const STATE_COOKIE: &str = "zhub_oauth_state";
pub const SESSION_SECONDS: i64 = 8 * 60 * 60;
pub const STATE_SECONDS: i64 = 10 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub user_id: u64,
    pub expires: i64,
    pub csrf: String,
}

/// 32 random bytes as url-safe text (CSRF tokens and the OAuth `state`).
pub fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    B64.encode(b)
}

fn mac(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

/// Signs `payload` into a cookie value.
pub fn seal(secret: &[u8], payload: &str) -> String {
    format!("{}.{}", B64.encode(payload), B64.encode(mac(secret, payload.as_bytes())))
}

/// Returns the payload only if the signature is valid.
pub fn open(secret: &[u8], value: &str) -> Option<String> {
    let (p, s) = value.split_once('.')?;
    let payload = B64.decode(p).ok()?;
    let given = B64.decode(s).ok()?;
    let want = mac(secret, &payload);
    if given.len() != want.len() || !bool::from(given.ct_eq(&want)) {
        return None;
    }
    String::from_utf8(payload).ok()
}

pub fn make_session_cookie_value(secret: &[u8], user_id: u64, now: i64) -> (String, String) {
    let csrf = random_token();
    let payload = format!("{user_id}|{}|{csrf}", now + SESSION_SECONDS);
    (seal(secret, &payload), csrf)
}

/// Reads a session from a cookie value. `allowed_user_id` is checked again on every request, so changing the
/// allowed id logs everyone else out at once.
pub fn read_session(secret: &[u8], value: &str, now: i64, allowed_user_id: u64) -> Option<Session> {
    let payload = open(secret, value)?;
    let mut parts = payload.splitn(3, '|');
    let user_id: u64 = parts.next()?.parse().ok()?;
    let expires: i64 = parts.next()?.parse().ok()?;
    let csrf = parts.next()?.to_string();
    if user_id != allowed_user_id || expires <= now || csrf.is_empty() {
        return None;
    }
    Some(Session { user_id, expires, csrf })
}

/// Constant-time comparison for the CSRF token and the OAuth state.
pub fn same(a: &str, b: &str) -> bool {
    !a.is_empty() && a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Finds one cookie in a `Cookie:` header value.
pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == name).then_some(v)
    })
}

/// `Set-Cookie` header value: HttpOnly, Secure, SameSite=Lax (Lax is needed so the cookie survives the redirect
/// back from GitHub; every state-changing request is a POST that also carries the CSRF token).
pub fn set_cookie(name: &str, value: &str, max_age: i64) -> String {
    format!("{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax")
}

pub fn clear_cookie(name: &str) -> String {
    format!("{name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-secret-test-secret-test-secret";
    const OWNER: u64 = 186391503;

    #[test]
    fn session_roundtrip() {
        let (cookie, csrf) = make_session_cookie_value(SECRET, OWNER, 1000);
        let s = read_session(SECRET, &cookie, 1001, OWNER).expect("valid session");
        assert_eq!(s.user_id, OWNER);
        assert_eq!(s.csrf, csrf);
    }

    #[test]
    fn expired_session_is_refused() {
        let (cookie, _) = make_session_cookie_value(SECRET, OWNER, 1000);
        assert!(read_session(SECRET, &cookie, 1000 + SESSION_SECONDS, OWNER).is_none());
        assert!(read_session(SECRET, &cookie, 1000 + SESSION_SECONDS + 1, OWNER).is_none());
    }

    #[test]
    fn other_user_is_refused() {
        let (cookie, _) = make_session_cookie_value(SECRET, 42, 1000);
        assert!(read_session(SECRET, &cookie, 1001, OWNER).is_none());
    }

    #[test]
    fn changed_allowed_user_logs_the_old_one_out() {
        let (cookie, _) = make_session_cookie_value(SECRET, OWNER, 1000);
        assert!(read_session(SECRET, &cookie, 1001, 999).is_none());
    }

    #[test]
    fn tampered_cookie_is_refused() {
        let (cookie, _) = make_session_cookie_value(SECRET, 42, 1000);
        // swap in a payload for the owner but keep the old signature
        let (_, sig) = cookie.split_once('.').unwrap();
        let forged = format!("{}.{}", B64.encode(format!("{OWNER}|99999999999|x")), sig);
        assert!(read_session(SECRET, &forged, 1001, OWNER).is_none());
        // flipped bit in the signature
        let (p, s) = cookie.split_once('.').unwrap();
        let mut bytes = B64.decode(s).unwrap();
        bytes[0] ^= 1;
        assert!(open(SECRET, &format!("{p}.{}", B64.encode(bytes))).is_none());
    }

    #[test]
    fn wrong_secret_is_refused() {
        let (cookie, _) = make_session_cookie_value(SECRET, OWNER, 1000);
        assert!(read_session(b"another-secret-another-secret-xx", &cookie, 1001, OWNER).is_none());
    }

    #[test]
    fn garbage_is_refused() {
        for v in ["", ".", "abc", "a.b", "!!!.???", "....."] {
            assert!(open(SECRET, v).is_none(), "{v:?}");
        }
    }

    #[test]
    fn csrf_compare() {
        assert!(same("abc", "abc"));
        assert!(!same("abc", "abd"));
        assert!(!same("abc", "ab"));
        assert!(!same("", ""));
    }

    #[test]
    fn cookie_header_parsing() {
        let h = "a=1; zhub_session=xyz.abc; b=2";
        assert_eq!(cookie_value(h, SESSION_COOKIE), Some("xyz.abc"));
        assert_eq!(cookie_value(h, "missing"), None);
        assert_eq!(cookie_value(h, "zhub"), None);
    }

    #[test]
    fn random_tokens_differ() {
        assert_ne!(random_token(), random_token());
        assert!(random_token().len() >= 43);
    }
}
