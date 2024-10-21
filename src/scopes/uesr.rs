use actix_web::{web, HttpResponse, Scope};
use chrono::{Utc, Duration};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm, TokenData, errors::Error as JwtError};
use serde::{Serialize, Deserialize};

use crate::extractors::authentication_token::AuthenticationToken;

pub fn user_scope() -> Scope {
    web::scope("/user")
        .route("/encode-token/{id}", web::get().to(encode_token))
        .route("/decode-token", web::post().to(decode_token))
        .route("/protected", web::get().to(protected))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncodeResponse {
    message: String,
    token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub id: usize,
    pub exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecodeBody {
    token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecodeResponse {
    message: String,
    id: usize,
}


async fn encode_token(path: web::Path<usize>, secret: web::Data<String>) -> HttpResponse {
    let id: usize = path.into_inner();
    let exp: usize = (Utc::now() + Duration::try_days(30).unwrap()).timestamp() as usize;
    let claims: Claims = Claims { id, exp };

    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_str().as_ref())).unwrap();

    HttpResponse::Ok().json(EncodeResponse {
        message: "success".to_string(),
        token
    })
}

async fn decode_token(body: web::Json<DecodeBody>, secret: web::Data<String>) -> HttpResponse {
    let decoded: Result<TokenData<Claims>, JwtError> = decode::<Claims>(
        &body.token, 
        &DecodingKey::from_secret(secret.as_str().as_ref()), 
        &Validation::new(Algorithm::HS256
    ));
    
    match decoded {
        Ok(token) => HttpResponse::Ok().json(DecodeResponse {
            message: "Authorized".to_string(),
            id: token.claims.id,
        }),
        Err(e) => HttpResponse::BadRequest().json(Response {message: e.to_string()}),
    }
}

async fn protected(auth_token: AuthenticationToken) -> HttpResponse {

    println!("{}", auth_token.id);

    HttpResponse::Ok().json(Response {message: "protected".to_string()})
}