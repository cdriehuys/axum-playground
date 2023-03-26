use std::net::SocketAddr;

use axum::{
    extract::{FromRef, State},
    routing::post,
    Json, Router,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, DecodingKey, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Clone)]
struct AppState {
    jwt_decoding_key: DecodingKey,
    jwt_encoding_key: EncodingKey,
}

impl FromRef<AppState> for DecodingKey {
    fn from_ref(state: &AppState) -> Self {
        state.jwt_decoding_key.clone()
    }
}

impl FromRef<AppState> for EncodingKey {
    fn from_ref(state: &AppState) -> Self {
        state.jwt_encoding_key.clone()
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let key = b"secret";
    let state = AppState {
        jwt_decoding_key: DecodingKey::from_secret(key),
        jwt_encoding_key: EncodingKey::from_secret(key),
    };

    let app = Router::new()
        .route("/tokens", post(create_token))
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:8000".parse().unwrap();
    info!(address = %addr, "Starting server.");

    axum::Server::bind(&"0.0.0.0:8000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn create_token(
    State(jwt_encoding_key): State<EncodingKey>,
    Json(payload): Json<CreateToken>,
) -> Json<TokenResponse> {
    let now = Utc::now();
    let exp = now + Duration::minutes(5);

    let claims = TokenClaims {
        exp: exp.timestamp(),
        name: payload.name,
    };

    let token =
        encode(&Header::default(), &claims, &jwt_encoding_key).expect("failed to encode token");

    Json(TokenResponse { token })
}

#[derive(Deserialize)]
struct CreateToken {
    name: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct TokenClaims {
    exp: i64,
    name: String,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
}
