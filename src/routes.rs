use crate::crypto::*;
use crate::AppState;
use actix_web::{web, HttpResponse};
use serde_json::json;

pub async fn encrypt(text: String, data: web::Data<AppState>) -> Result<String, HttpResponse> {
    Ok(encrypt_depth_1(
        serde_json::from_str(&text).map_err(|e| HttpResponse::BadRequest().body(e.to_string()))?,
        data.public_key.clone(),
    )
    .map_err(|e| HttpResponse::BadRequest().body(e))?
    .to_string())
}

pub async fn decrypt(text: String, data: web::Data<AppState>) -> Result<String, HttpResponse> {
    Ok(serde_json::to_string(
        &detect_and_decrypt(
            serde_json::from_str(&text)
                .map_err(|e| HttpResponse::BadRequest().body(e.to_string()))?,
            &data.private_key,
        )
        .map_err(|e| HttpResponse::BadRequest().body(e))?,
    )
    .map_err(|_| HttpResponse::BadRequest())?)
}

pub async fn sign(text: String, data: web::Data<AppState>) -> Result<String, HttpResponse> {
    Ok(json! {
        {
            "signature": get_signature(
                serde_json::from_str(&text).map_err(|e| HttpResponse::BadRequest().body(e.to_string()))?,
                &data.private_key,
            )?
        }
    }
    .to_string())
}

pub async fn verify(text: String, data: web::Data<AppState>) -> Result<HttpResponse, HttpResponse> {
    if Ok(true)
        == get_verification(
            serde_json::from_str(&text)
                .map_err(|e| HttpResponse::BadRequest().body(e.to_string()))?,
            &data.public_key,
        )
    {
        Ok(HttpResponse::NoContent().finish())
    } else {
        Err(HttpResponse::BadRequest().finish())
    }
}
