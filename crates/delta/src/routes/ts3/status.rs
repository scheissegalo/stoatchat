use revolt_config::config;
use rocket::serde::json::Json;
use schemars::JsonSchema;
use serde::Serialize;

#[derive(Serialize, JsonSchema)]
pub struct Ts3Status {
    pub enabled: bool,
}

#[openapi(tag = "Account")]
#[get("/status")]
pub async fn status() -> Json<Ts3Status> {
    Json(Ts3Status {
        enabled: config().await.ts3_auth.enabled,
    })
}
