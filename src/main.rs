use actix_web::FromRequest;
use actix_web::{web, App, HttpServer, Responder};
use rand::rngs::OsRng;

mod crypto;
mod routes;

#[derive(Clone)]
pub struct AppState {
    public_key: rsa::RsaPublicKey,
    private_key: rsa::RsaPrivateKey,
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
    };
    HttpServer::new(move || {
        use routes::*;
        App::new()
            .data(data.clone())
            // limit size of payload
            .app_data(String::configure(|cfg| cfg.limit(4096)))
            .route("/", web::get().to(greet))
            .route("/encrypt", web::get().to(encrypt))
            .route("/decrypt", web::get().to(decrypt))
            .route("/sign", web::get().to(sign))
            .route("/verify", web::get().to(verify))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
