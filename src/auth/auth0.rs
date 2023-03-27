use std::collections::HashMap;

use jsonwebtoken::{
    decode, decode_header,
    jwk::{self, AlgorithmParameters},
    DecodingKey, TokenData, Validation,
};
use serde::de::DeserializeOwned;
use thiserror::Error;
use tracing::{debug, info};

#[derive(Clone)]
pub struct KeySet {
    keys: HashMap<String, Key>,
}

impl KeySet {
    pub async fn from_url(url: &str) -> Result<Self, KeyError> {
        debug!(%url, "Fetching JSON Web Key Set.");
        let jwks: jwk::JwkSet = reqwest::get(url).await?.json().await?;

        info!(%url, count = jwks.keys.len(), "Successfully pulled JSON Web Key Set.");

        let mut keys = HashMap::new();
        for jwk in jwks.keys {
            let kid = jwk.common.key_id.ok_or(KeyError::MissingKeyId)?;

            match &jwk.algorithm {
                jwk::AlgorithmParameters::RSA(rsa) => {
                    let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e)?;
                    let validation =
                        Validation::new(jwk.common.algorithm.ok_or(KeyError::MissingAlgorithm)?);

                    keys.insert(
                        kid,
                        Key {
                            decoding: decoding_key,
                            validation,
                        },
                    );
                }
                other => {
                    return Err(KeyError::UnexpectedAlgorithm {
                        kid,
                        algorithm: other.to_owned(),
                    })
                }
            }
        }

        Ok(Self { keys })
    }

    pub fn validate_claims<T>(&self, token: &str) -> Result<T, AuthError>
    where
        T: DeserializeOwned,
    {
        let header = decode_header(token).map_err(|err| AuthError::InvalidHeader(err))?;
        let kid = header.kid.ok_or(AuthError::MissingKeyId)?;

        let key = self
            .keys
            .get(&kid)
            .ok_or_else(|| AuthError::UnknownKeyId(kid))?;

        let decoded_token: TokenData<T> = decode(token, &key.decoding, &key.validation)?;

        Ok(decoded_token.claims)
    }
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("token header is malformed")]
    InvalidHeader(jsonwebtoken::errors::Error),

    #[error("token is invalid")]
    InvalidToken(#[from] jsonwebtoken::errors::Error),

    #[error("token does not specify a `kid` field in its header")]
    MissingKeyId,

    #[error("unknown key id {0:?}")]
    UnknownKeyId(String),
}

#[derive(Clone)]
struct Key {
    decoding: DecodingKey,
    validation: Validation,
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("failed to fetch keys")]
    HttpError(#[from] reqwest::Error),

    #[error("invalid key components")]
    InvalidComponents(#[from] jsonwebtoken::errors::Error),

    #[error("key does not specify an algorithm")]
    MissingAlgorithm,

    #[error("key missing `kid` attribute")]
    MissingKeyId,

    #[error("found key {kid} with unexpected (not RSA) algorithm: {algorithm:?}")]
    UnexpectedAlgorithm {
        kid: String,
        algorithm: AlgorithmParameters,
    },
}
