use crate::errors::ServiceError;
use argonautica::{Hasher, Verifier};


////todo for jwt auth
//use models::SlimUser;
//use std::convert::From;
//use jwt::{decode, encode, Header, Validation};
//use chrono::{Local, Duration};


lazy_static::lazy_static! {
pub  static ref SECRET_KEY: String = std::env::var("SECRET_KEY").unwrap_or_else(|_| "0123".repeat(8));
}

// WARNING THIS IS ONLY FOR DEMO PLEASE DO MORE RESEARCH FOR PRODUCTION USE
pub fn hash_password(password: &str) -> Result<String, ServiceError> {
    Hasher::default()
        .with_password(password)
        .with_secret_key(SECRET_KEY.as_str())
        .hash()
        .map_err(|err| {
            dbg!(err);
            ServiceError::InternalServerError
        })
}

pub fn verify(hash: &str, password: &str) -> Result<bool, ServiceError> {
    Verifier::default()
        .with_hash(hash)
        .with_password(password)
        .with_secret_key(SECRET_KEY.as_str())
        .verify()
        .map_err(|err| {
            dbg!(err);
            ServiceError::Unauthorized
        })
}


////todo for jwt auth
//#[derive(Debug, Serialize, Deserialize)]
//struct Claims {
//    // issuer
//    iss: String,
//    // subject
//    sub: String,
//    // issued at
//    iat: i64,
//    // expiry
//    exp: i64,
//    // user email
//    email: String,
//}

//impl Claims {
//    fn with_email(email: &str) -> Self {
//        Claims {
//            iss: "localhost".into(),
//            sub: "auth".into(),
//            email: email.to_owned(),
//            iat: Local::now().timestamp(),
//            exp: (Local::now() + Duration::hours(24)).timestamp(),
//        }
//    }
//}

//impl From<Claims> for SlimUser {
//    fn from(claims: Claims) -> Self {
//        SlimUser { email: claims.email }
//    }
//}

//pub fn create_token(data: &SlimUser) -> Result<String, ServiceError> {
//    let claims = Claims::with_email(data.email.as_str());
//    encode(&Header::default(), &claims, get_secret().as_ref())
//        .map_err(|_err| ServiceError::InternalServerError)
//}

//pub fn decode_token(token: &str) -> Result<SlimUser, ServiceError> {
//    decode::<Claims>(token, get_secret().as_ref(), &Validation::default())
//        .map(|data| Ok(data.claims.into()))
//        .map_err(|_err| ServiceError::Unauthorized)?
//}

//fn get_secret() -> String {
//    env::var("JWT_SECRET").unwrap_or("my secret".into())
//}
