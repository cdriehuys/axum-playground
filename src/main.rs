use std::net::SocketAddr;

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, State},
    headers::{authorization::Bearer, Authorization},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, RequestPartsExt, Router, TypedHeader,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

use axum_playground::auth;

#[derive(Clone)]
struct AppState {
    keys: auth::Keys,
}

impl FromRef<AppState> for auth::Keys {
    fn from_ref(state: &AppState) -> Self {
        state.keys.clone()
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let key = b"secret";
    let state = AppState {
        keys: auth::Keys::from_secret(key),
    };

    let app = Router::new()
        .route("/tokens", post(create_token))
        .route("/whoami", get(whoami))
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:8000".parse().unwrap();
    info!(address = %addr, "Starting server.");

    axum::Server::bind(&"0.0.0.0:8000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn create_token(
    State(jwt_keys): State<auth::Keys>,
    Json(payload): Json<CreateToken>,
) -> Json<TokenResponse> {
    let now = Utc::now();
    let exp = now + Duration::minutes(5);

    let claims = TokenClaims {
        exp: exp.timestamp(),
        name: payload.name,
    };

    let token =
        encode(&Header::default(), &claims, jwt_keys.encoding()).expect("failed to encode token");

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

#[async_trait]
impl<S> FromRequestParts<S> for TokenClaims
where
    auth::Keys: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jwt_keys = auth::Keys::from_ref(state);

        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::MissingCredentials)?;

        let token_data =
            decode::<TokenClaims>(bearer.token(), jwt_keys.decoding(), &Validation::default())
                .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

async fn whoami(
    claims: TokenClaims,
    State(_state): State<AppState>,
) -> Result<Json<WhoAmI>, AuthError> {
    Ok(Json(WhoAmI { name: claims.name }))
}

#[derive(Serialize)]
struct WhoAmI {
    name: String,
}

#[derive(Debug)]
enum AuthError {
    InvalidToken,
    MissingCredentials,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token."),
            Self::MissingCredentials => (StatusCode::UNAUTHORIZED, "No token provided."),
        };

        let body = Json(json!({
            "error": message,
        }));

        (status, body).into_response()
    }
}
