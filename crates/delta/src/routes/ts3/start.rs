use nanoid::nanoid;
use revolt_config::config;
use redis_kiss::AsyncCommands;
use revolt_database::util::shield::ShieldValidationInput;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;

use super::{
    call_sidecar, challenge_key, check_rate_limit, Challenge, ChallengeCandidate,
    SidecarCandidates, Ts3Candidate, Ts3StartResponse,
};

#[openapi(tag = "Account")]
#[post("/start")]
pub async fn start(shield: ShieldValidationInput) -> Result<Json<Ts3StartResponse>> {
    let config = config().await;

    if !config.ts3_auth.enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "ts3_auth".into()
        }));
    }

    let ip = shield.ip.unwrap_or_default();
    if ip.is_empty() {
        return Err(create_error!(InternalError));
    }

    check_rate_limit(&format!("ts3:rate:start:{ip}"), 10, 600).await?;

    let sidecar: SidecarCandidates = call_sidecar(
        "/candidates",
        &serde_json::json!({ "ip": ip }),
    )
    .await?;

    let candidates: Vec<ChallengeCandidate> = sidecar
        .candidates
        .into_iter()
        .map(|candidate| ChallengeCandidate {
            id: nanoid!(12),
            uid: candidate.uid,
            nickname: candidate.nickname,
        })
        .collect();

    let challenge_id = nanoid!(32);
    let challenge = Challenge {
        ip,
        candidates: candidates.clone(),
        selected_uid: None,
        code_hash: None,
        attempts: 0,
        expires: 0,
    };

    let mut conn = redis_kiss::get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?;
    let payload =
        serde_json::to_string(&challenge).map_err(|_| create_error!(InternalError))?;
    let _: () = conn
        .set_ex(challenge_key(&challenge_id), payload, 600)
        .await
        .map_err(|_| create_error!(InternalError))?;

    Ok(Json(Ts3StartResponse {
        challenge_id,
        candidates: candidates
            .into_iter()
            .map(|candidate| Ts3Candidate {
                id: candidate.id,
                nickname: candidate.nickname,
            })
            .collect(),
        fallback: sidecar.fallback,
    }))
}
