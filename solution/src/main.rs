use actix_web::FromRequest;
use actix_web::{web, App, HttpServer, Responder};
use rand::rngs::OsRng;
use std::sync::Arc;
use std::sync::RwLock;

mod crypto;
mod routes;

#[derive(Clone)]
pub struct AppState {
    public_key: rsa::RsaPublicKey,
    private_key: rsa::RsaPrivateKey,
    fields_to_encrypt: Arc<RwLock<Vec<String>>>,
}

async fn greet() -> impl Responder {
    "Bonjour! No need to look at this page. Go encrypt some things.".to_string()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let (public_key, private_key) = crypto::load_keys("pub_key", "priv_key", &mut OsRng);
    println!("Keys loaded / generated");
    let data = AppState {
        public_key,
        private_key,
        fields_to_encrypt: Arc::new(RwLock::new(vec![])),
    };
    HttpServer::new(move || {
        use routes::*;
        App::new()
            .data(data.clone())
            // limit size of payload
            .app_data(String::configure(|cfg| cfg.limit(4096)))
            .route("/", web::get().to(greet))
            .route("/encrypt", web::post().to(encrypt))
            .route("/decrypt", web::post().to(decrypt))
            .route("/sign", web::post().to(sign))
            .route("/verify", web::post().to(verify))
            .route("/config", web::post().to(config))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
