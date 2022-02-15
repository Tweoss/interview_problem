use serde_json::{json, Value};

mod checks;

async fn run_tests(base_url: &str, client: &reqwest::Client, bodies: Vec<(String, Value)>) {
    use checks::*;
    for (name, body) in bodies {
        println!("== Running test {} ==", name);
        let encrypted = test_encrypt(base_url, client, &body).await.unwrap();
        println!("encryption passed");
        test_decrypt(base_url, client, &encrypted, &body)
            .await
            .unwrap();
        println!("decryption passed");
        let signature = test_signature(base_url, client, &body).await.unwrap();
        println!("signature passed");
        test_verification(base_url, client, &encrypted, &signature)
            .await
            .unwrap();
        println!("verification passed");
    }
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
                }
            )
        ],
    )
    .await;
    Ok(())
}
