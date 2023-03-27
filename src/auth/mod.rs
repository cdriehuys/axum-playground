// Authenticate:
// 1. Pass credentials
// 2. Persist hashed refresh token
// 3. Return access token and refresh token
//
// Check:
// 1. Parse token from request
// 2. Validate token
//
// Refresh:
// 1. Look up refresh token
// 2. Validate
// 3. Deliver new access token

pub mod auth0;

use jsonwebtoken::{DecodingKey, EncodingKey};

/// Container for the keys used to decode/encode JWTs.
#[derive(Clone)]
pub struct Keys {
    decoding: DecodingKey,
    encoding: EncodingKey,
}

impl Keys {
    /// Create a new key container based on the provided secret.
    pub fn from_secret(secret: &[u8]) -> Self {
        Self {
            decoding: DecodingKey::from_secret(secret),
            encoding: EncodingKey::from_secret(secret),
        }
    }

    pub fn decoding(&self) -> &DecodingKey {
        &self.decoding
    }

    pub fn encoding(&self) -> &EncodingKey {
        &self.encoding
    }
}
