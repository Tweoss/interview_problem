use colored::Colorize;
use serde_json::{json, Value};

mod checks;
mod negative_checks;

async fn run_tests(base_url: &str, client: &reqwest::Client, bodies: Vec<(String, Value)>) {
    use checks::*;
    println!("{}", "==== Running Positive Tests ====".blue().bold());
    for (name, body) in bodies {
        println!("{}", format!("== Running test {} ==", name).blue());
        let encrypted = test_encrypt(base_url, client, &body).await.unwrap();
        println!("{}", "encryption passed".green());
        test_decrypt(base_url, client, &encrypted, &body)
            .await
            .unwrap();
        println!("{}", "decryption passed".green());
        let signature = test_signature(base_url, client, &body).await.unwrap();
        println!("{}", "signature passed".green());
        test_verification(base_url, client, &encrypted, &signature)
            .await
            .unwrap();
        println!("{}", "verification passed".green());
    }
}

async fn run_negative_tests(base_url: &str, client: &reqwest::Client) {
    use negative_checks::*;
    println!("{}", "==== Running Negative Tests ====".blue().bold());
    test_encrypt_empty(base_url, client).await.unwrap();
    println!("{}", "encrypting empty passed".green());
    test_encrypt_array_first(base_url, client).await.unwrap();
    println!("{}", "encrypting array first passed".green());
    test_decrypt_empty(base_url, client).await.unwrap();
    println!("{}", "decrypting empty passed".green());
    test_signature_invalid(base_url, client).await.unwrap();
    println!("{}", "signing invalid passed".green());
    test_verify_missing_signature(base_url, client)
        .await
        .unwrap();
    println!("{}", "verifying missing signature passed".green());
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8080";
    run_tests(
        base_url,
        &client,
        vec![
            (
                "test1".to_string(),
                json! {
                    {
                        "array of sun": [
                            { "bonjour": "heyo" },
                            { "hoi": "NUUUU" },
                            "a doe a deer"
                        ],
                        "comment ça va?": "très bien",
                        "nest me an egg": {
                            "abcd": [
                                { "one": "a" },
                                { "two": "b" },
                                { "three": "c" }
                            ]
                        }
                    }
                },
            ),
            (
                "test2".to_string(),
                json! {
                    {
                        "comment ça va?": "très bien",
                        "nest me an double": {
                            "abcd": [
                                {
                                    "one": ["two", "three", {"four": {"five": "six"}}]
                                },
                            ]
                        }
                    }
                },
            ),
            (
                "test3".to_string(),
                json! {
                    {
                        "nice": "to meet you",
                    }
                },
            ),
        ],
    )
    .await;
    run_negative_tests(base_url, &client).await;
    Ok(())
}
