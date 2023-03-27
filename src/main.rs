use std::net::SocketAddr;

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    headers::{authorization::Bearer, Authorization},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, RequestPartsExt, Router, TypedHeader,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use axum_playground::auth::{self, auth0};

#[derive(Clone)]
struct AppState {
    keys: auth::auth0::KeySet,
}

impl FromRef<AppState> for auth::auth0::KeySet {
    fn from_ref(state: &AppState) -> Self {
        state.keys.clone()
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "axum_playground=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let auth0_keys =
        auth0::KeySet::from_url("https://dev-hn7maq8cvpmas5mn.us.auth0.com/.well-known/jwks.json")
            .await
            .expect("Failed to fetch JWKS");

    let state = AppState { keys: auth0_keys };

    let app = Router::new()
        .route("/whoami", get(whoami))
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:8000".parse().unwrap();
    info!(address = %addr, "Starting server.");

    axum::Server::bind(&"0.0.0.0:8000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Debug)]
struct Token(String);

#[async_trait]
impl<S> FromRequestParts<S> for Token {
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::MissingCredentials)?;

        Ok(Self(bearer.token().to_owned()))
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct TokenClaims {
    iss: String,
    sub: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for TokenClaims
where
    auth::auth0::KeySet: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token = Token::from_request_parts(parts, state).await?;
        let jwt_keys = auth::auth0::KeySet::from_ref(state);

        let claims: Self = jwt_keys.validate_claims(&token.0).map_err(|error| {
            debug!(%error, "Received invalid token.");

            AuthError::InvalidToken
        })?;

        Ok(claims)
    }
}

async fn whoami(access_token: Token, claims: TokenClaims) -> Result<Json<WhoAmI>, AuthError> {
    let profile_url = format!("{}userinfo", &claims.iss);
    debug!(profile_url, ?access_token, "Retrieving user profile.");
    let client = reqwest::Client::new();
    let profile: Auth0Profile = client
        .get(profile_url)
        .bearer_auth(&access_token.0)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    info!(?profile, "Retrieved user profile.");

    Ok(Json(WhoAmI {
        id: profile.sub,
        name: profile.name,
        email: profile.email,
    }))
}

#[derive(Serialize)]
struct WhoAmI {
    id: String,
    name: String,
    email: String,
}

#[derive(Debug, Deserialize)]
struct Auth0Profile {
    email: String,
    name: String,
    sub: String,
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
