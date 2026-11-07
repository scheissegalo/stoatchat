use rand::Rng;
use redis_kiss::AsyncCommands;
use revolt_config::config;
use revolt_database::util::shield::ShieldValidationInput;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use schemars::JsonSchema;
use serde::Deserialize;

use super::{
    call_sidecar, challenge_key, check_rate_limit, hash_code, Challenge, Ts3SendResponse,
};

#[derive(Deserialize, JsonSchema)]
pub struct DataTs3Send {
    pub challenge_id: String,
    pub candidate_id: String,
}

#[openapi(tag = "Account")]
#[post("/send", data = "<data>")]
pub async fn send(
    shield: ShieldValidationInput,
    data: Json<DataTs3Send>,
) -> Result<Json<Ts3SendResponse>> {
    let config = config().await;

    if !config.ts3_auth.enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "ts3_auth".into()
        }));
    }

    let ip = shield.ip.unwrap_or_default();
    let data = data.into_inner();

    let mut conn = redis_kiss::get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?;
    let raw: Option<String> = conn
        .get(challenge_key(&data.challenge_id))
        .await
        .map_err(|_| create_error!(InternalError))?;
    let mut challenge: Challenge = serde_json::from_str(
        &raw.ok_or_else(|| create_error!(NotFound))?,
    )
    .map_err(|_| create_error!(InternalError))?;

    if challenge.ip != ip {
        return Err(create_error!(InvalidToken));
    }

    let candidate = challenge
        .candidates
        .iter()
        .find(|candidate| candidate.id == data.candidate_id)
        .cloned()
        .ok_or_else(|| create_error!(NotFound))?;

    check_rate_limit(
        &format!("ts3:rate:uid:{}", candidate.uid),
        3,
        600,
    )
    .await?;

    let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000u32));
    let code_hash = hash_code(&code, &data.challenge_id);
    let expires = chrono::Utc::now().timestamp() + config.ts3_auth.code_ttl as i64;
    let message = format!(
        "North Chat verification code: {code}\n\
         This code expires in {} minutes. If you did not request it, ignore this message.",
        config.ts3_auth.code_ttl / 60
    );

    call_sidecar::<serde_json::Value>(
        "/send",
        &serde_json::json!({
            "uid": candidate.uid,
            "message": message,
        }),
    )
    .await?;

    challenge.selected_uid = Some(candidate.uid);
    challenge.code_hash = Some(code_hash);
    challenge.attempts = 0;
    challenge.expires = expires;

    let payload =
        serde_json::to_string(&challenge).map_err(|_| create_error!(InternalError))?;
    let _: () = conn
        .set_ex(challenge_key(&data.challenge_id), payload, 600)
        .await
        .map_err(|_| create_error!(InternalError))?;

    Ok(Json(Ts3SendResponse {
        ok: true,
        expires_at: expires,
        nickname: candidate.nickname,
    }))
}
