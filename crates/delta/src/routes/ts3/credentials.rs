use revolt_config::config;
use revolt_database::{
    util::{
        email::{normalise_email, validate_email},
        password::{assert_safe, hash_password},
    },
    Account, Database, EmailVerification,
};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Deserialize, JsonSchema)]
pub struct DataTs3Credentials {
    pub email: String,
    pub password: String,
}

/// Set a real email and password on a TeamSpeak-created account.
///
/// This lets a TS3 user keep an email/password fallback in case their TS3
/// identity changes or they lose the client installation. Only accounts with
/// the synthetic TS3 email domain can use this endpoint; normal accounts must
/// use the regular change-email/change-password flows.
#[openapi(tag = "Account")]
#[post("/credentials", data = "<data>")]
pub async fn credentials(
    db: &State<Database>,
    mut account: Account,
    data: Json<DataTs3Credentials>,
) -> Result<EmptyResponse> {
    let config = config().await;

    if !config.ts3_auth.enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "ts3_auth".into()
        }));
    }

    let suffix = format!("@{}", config.ts3_auth.synthetic_email_domain);
    if !account.email.ends_with(&suffix) {
        return Err(create_error!(IncorrectData {
            with: "this account already has credentials".into()
        }));
    }

    let data = data.into_inner();
    validate_email(&data.email)?;
    assert_safe(&data.password).await?;

    let normalised = normalise_email(data.email.clone());
    if let Some(existing) = db.fetch_account_by_normalised_email(&normalised).await?
        && existing.id != account.id
    {
        return Err(create_error!(IncorrectData {
            with: "email already in use".into()
        }));
    }

    account.email = data.email;
    account.email_normalised = normalised;
    account.password = hash_password(data.password)?;
    account.verification = EmailVerification::Verified;
    account.save(db).await?;

    Ok(EmptyResponse)
}
