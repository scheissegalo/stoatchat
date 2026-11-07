use chrono::Utc;
use redis_kiss::AsyncCommands;
use revolt_config::config;
use revolt_database::{
    util::{email::normalise_email, shield::ShieldValidationInput},
    Account, Database,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use schemars::JsonSchema;
use serde::Deserialize;

use super::{
    challenge_key, constant_time_eq, hash_code, synthetic_email, ts3_uid_hash, Challenge,
};

#[derive(Deserialize, JsonSchema)]
pub struct DataTs3Verify {
    pub challenge_id: String,
    pub code: String,
}

#[openapi(tag = "Account")]
#[post("/verify", data = "<data>")]
pub async fn verify(
    db: &State<Database>,
    shield: ShieldValidationInput,
    data: Json<DataTs3Verify>,
) -> Result<Json<v0::Session>> {
    let config = config().await;

    if !config.ts3_auth.enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "ts3_auth".into()
        }));
    }

    let ip = shield.ip.unwrap_or_default();
    let data = data.into_inner();

    if data.code.len() != 6 || !data.code.chars().all(|c| c.is_ascii_digit()) {
        return Err(create_error!(InvalidToken));
    }

    let mut conn = redis_kiss::get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?;
    let raw: Option<String> = conn
        .get(challenge_key(&data.challenge_id))
        .await
        .map_err(|_| create_error!(InternalError))?;
    let mut challenge: Challenge = serde_json::from_str(
        &raw.ok_or_else(|| create_error!(InvalidToken))?,
    )
    .map_err(|_| create_error!(InternalError))?;

    if challenge.ip != ip || challenge.expires < Utc::now().timestamp() {
        return Err(create_error!(InvalidToken));
    }

    let code_hash = challenge
        .code_hash
        .clone()
        .ok_or_else(|| create_error!(InvalidToken))?;
    let selected_uid = challenge
        .selected_uid
        .clone()
        .ok_or_else(|| create_error!(InvalidToken))?;

    let provided = hash_code(&data.code, &data.challenge_id);
    if !constant_time_eq(provided.as_bytes(), code_hash.as_bytes()) {
        challenge.attempts += 1;

        if challenge.attempts >= config.ts3_auth.max_attempts {
            let _: i64 = conn
                .del(challenge_key(&data.challenge_id))
                .await
                .map_err(|_| create_error!(InternalError))?;
        } else {
            let payload =
                serde_json::to_string(&challenge).map_err(|_| create_error!(InternalError))?;
            let _: () = conn
                .set_ex(challenge_key(&data.challenge_id), payload, 600)
                .await
                .map_err(|_| create_error!(InternalError))?;
        }

        return Err(create_error!(InvalidToken));
    }

    let _: i64 = conn
        .del(challenge_key(&data.challenge_id))
        .await
        .map_err(|_| create_error!(InternalError))?;

    let uid_hash = ts3_uid_hash(&selected_uid);
    let email = synthetic_email(&selected_uid, &config.ts3_auth.synthetic_email_domain);
    let normalised = normalise_email(email.clone());

    let account = if let Some(account) = db.fetch_account_by_ts3_uid(&uid_hash).await? {
        // The user may have added a real email/password since the account was
        // created; the TS3 UID link still points at the same account.
        account
    } else if let Some(mut account) = db.fetch_account_by_normalised_email(&normalised).await? {
        // Older TS3 account created before the ts3_uid field existed.
        account.ts3_uid = Some(uid_hash);
        account.save(db).await?;
        account
    } else {
        let mut account = Account::new(db, email, nanoid::nanoid!(32), false).await?;
        account.ts3_uid = Some(uid_hash);
        account.save(db).await?;
        account
    };

    if account.disabled {
        return Err(create_error!(InvalidCredentials));
    }

    let session = account
        .create_session(db, "North Chat Web (TeamSpeak)".to_string())
        .await?;

    Ok(Json(session.into()))
}
