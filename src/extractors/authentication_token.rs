use std::future::{ready, Ready};

use actix_web::{web, dev::Payload, http::{self, header::HeaderValue}, Error as ActixWebError, FromRequest, HttpRequest, error::ErrorUnauthorized};
use jsonwebtoken::{TokenData, decode, DecodingKey, Validation, Algorithm, errors::Error as JwtError};
use serde::{Serialize, Deserialize};

use crate::scopes::uesr::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationToken {
    pub id: usize,
}

impl FromRequest for AuthenticationToken {
    type Error = ActixWebError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let auth_header: Option<&HeaderValue> = req.headers().get(http::header::AUTHORIZATION);
        let auth_token: String = auth_header.unwrap().to_str().unwrap_or("").to_string();
        if auth_token.is_empty() {
            return ready(Err(ErrorUnauthorized("invalid token")));
        }

        let secret: String = req.app_data::<web::Data<String>>().unwrap().clone().into_inner().to_string();

        let decode: Result<TokenData<Claims>,JwtError> = decode::<Claims>(
            &auth_token, 
            &DecodingKey::from_secret(secret.as_str().as_ref()), 
            &Validation::new(Algorithm::HS256)
        );

        match decode {
            Ok(token) => ready(Ok(AuthenticationToken { id: token.claims.id })),
            Err(_) => ready(Err(ErrorUnauthorized("unauthorized")))
        }
    }
}