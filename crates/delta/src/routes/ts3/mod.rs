use std::sync::LazyLock;

use redis_kiss::AsyncCommands;
use revolt_result::{create_error, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod credentials;
pub mod send;
pub mod start;
pub mod status;
pub mod verify;

/// Shared HTTP client for the internal TS3 sidecar.
pub static SIDECAR_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);

/// A pending TeamSpeak verification challenge, stored in Redis.
#[derive(Serialize, Deserialize, Clone)]
pub struct Challenge {
    /// IP of the web client that started the challenge
    pub ip: String,
    /// Online TS3 clients the user can select from
    pub candidates: Vec<ChallengeCandidate>,
    /// Selected TS3 unique identifier
    pub selected_uid: Option<String>,
    /// SHA-256 of the code and challenge id
    pub code_hash: Option<String>,
    /// Failed verification attempts
    pub attempts: u32,
    /// Unix timestamp when the code expires
    pub expires: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ChallengeCandidate {
    /// Opaque id shown to the web client
    pub id: String,
    /// TS3 unique identifier, never sent to the web client
    pub uid: String,
    pub nickname: String,
}

#[derive(Deserialize)]
pub struct SidecarCandidates {
    pub candidates: Vec<SidecarCandidate>,
    pub fallback: bool,
}

#[derive(Deserialize)]
pub struct SidecarCandidate {
    pub uid: String,
    pub nickname: String,
}

#[derive(Serialize, JsonSchema)]
pub struct Ts3Candidate {
    pub id: String,
    pub nickname: String,
}

#[derive(Serialize, JsonSchema)]
pub struct Ts3StartResponse {
    pub challenge_id: String,
    pub candidates: Vec<Ts3Candidate>,
    /// true when the IP matched nobody and the sidecar returned all clients
    pub fallback: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct Ts3SendResponse {
    pub ok: bool,
    pub expires_at: i64,
    pub nickname: String,
}

pub fn routes() -> (
    Vec<rocket::Route>,
    revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi,
) {
    openapi_get_routes_spec![
        status::status,
        start::start,
        send::send,
        verify::verify,
        credentials::credentials
    ]
}

pub async fn call_sidecar<T: serde::de::DeserializeOwned>(
    path: &str,
    body: &serde_json::Value,
) -> Result<T> {
    let config = revolt_config::config().await;
    let url = format!("{}{}", config.ts3_auth.url.trim_end_matches('/'), path);

    let response = SIDECAR_CLIENT
        .post(url)
        .header("x-internal-secret", &config.ts3_auth.secret)
        .json(body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|error| {
            log::error!("TS3 sidecar request failed: {error}");
            create_error!(InternalError)
        })?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(create_error!(NotFound));
    }

    if !response.status().is_success() {
        log::error!("TS3 sidecar returned {}", response.status());
        return Err(create_error!(InternalError));
    }

    response.json::<T>().await.map_err(|error| {
        log::error!("TS3 sidecar returned an invalid response: {error}");
        create_error!(InternalError)
    })
}

pub async fn check_rate_limit(key: &str, limit: i64, window: usize) -> Result<()> {
    let mut conn = redis_kiss::get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?;

    let count: i64 = conn
        .incr(key, 1)
        .await
        .map_err(|_| create_error!(InternalError))?;

    if count == 1 {
        let _: i64 = conn
            .expire(key, window)
            .await
            .map_err(|_| create_error!(InternalError))?;
    }

    if count > limit {
        return Err(create_error!(InSlowmode {
            retry_after: window as u64,
        }));
    }

    Ok(())
}

pub fn challenge_key(id: &str) -> String {
    format!("ts3:challenge:{id}")
}

pub fn hash_code(code: &str, challenge_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hasher.update(b":");
    hasher.update(challenge_id.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut difference = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        difference |= left ^ right;
    }

    difference == 0
}

pub fn ts3_uid_hash(uid: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(uid.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn synthetic_email(uid: &str, domain: &str) -> String {
    let hash = ts3_uid_hash(uid);
    format!("ts3+{}@{}", &hash[..32], domain)
}
