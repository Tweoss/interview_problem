use serde_json::json;

/// Errors if
/// * no body is received
/// * the response is not a 400 Bad Request with a specific parsing error message
pub async fn test_encrypt_empty(base_url: &str, client: &reqwest::Client) -> Result<(), String> {
    let url = format!("{}/encrypt", base_url);
    let response = client
        .post(&url)
        .body("")
        .send()
        .await
        .map_err(|_| "Failed to send request")?;
    if response.status() != 400 {
        return Err("Expected 400 Bad Request status code in encryption".to_string());
    }
    let body = response
        .text()
        .await
        .map_err(|_| "Failed to receive response with body from encryption")?;
    if body != "EOF while parsing a value at line 1 column 0" {
        return Err("Expected EOF while parsing a nonexistent value in encryption".to_string());
    }
    Ok(())
}

/// Errors if
/// * no body is received
/// * the response is not a 400 Bad Request with a specific parsing error message
pub async fn test_encrypt_array_first(
    base_url: &str,
    client: &reqwest::Client,
) -> Result<(), String> {
    let url = format!("{}/encrypt", base_url);
    let response = client
        .post(&url)
        .body(json!(["hin", "hoi"]).to_string())
        .send()
        .await
        .map_err(|_| "Failed to send request")?;
    if response.status() != 400 {
        return Err("Expected 400 Bad Request status code in encryption".to_string());
    }
    let body = response
        .text()
        .await
        .map_err(|_| "Failed to receive response with body from encryption")?;
    if body != "data must be a json map on the first level" {
        return Err(
            "Expected data must be a json map on the first level in encryption".to_string(),
        );
    }
    Ok(())
}

/// Errors if
/// * no body is received
/// * the decryption response is not a 400 Bad Request with a specific parsing error message
pub async fn test_decrypt_empty(base_url: &str, client: &reqwest::Client) -> Result<(), String> {
    let url = format!("{}/decrypt", base_url);
    let response = client
        .post(&url)
        .body("")
        .send()
        .await
        .map_err(|_| "Failed to send request")?;
    if response.status() != 400 {
        return Err("Expected 400 Bad Request status code in decryption".to_string());
    }
    let body = response
        .text()
        .await
        .map_err(|_| "Failed to receive response with body from decryption")?;
    if body != "EOF while parsing a value at line 1 column 0" {
        return Err("Expected EOF while parsing a nonexistent value in decryption".to_string());
    }
    Ok(())
}

/// Errors if
/// * no body is received
/// * the decryption response is not a 400 Bad Request with a specific parsing error message
pub async fn test_signature_invalid(
    base_url: &str,
    client: &reqwest::Client,
) -> Result<(), String> {
    let url = format!("{}/sign", base_url);
    let response = client
        .post(&url)
        .body("abcdefg, this is not valid json, hijklmnop.")
        .send()
        .await
        .map_err(|_| "Failed to send request")?;
    if response.status() != 400 {
        return Err("Expected 400 Bad Request status code from signature".to_string());
    }
    let body = response
        .text()
        .await
        .map_err(|_| "Failed to receive response with body from signature")?;
    if body != "expected value at line 1 column 1" {
        return Err("Expected expected value at line 1 column 1".to_string());
    }

    Ok(())
}

/// Errors if
/// * no body is received
/// * the decryption response is not a 400 Bad Request with a specific parsing error message
pub async fn test_verify_missing_signature(
    base_url: &str,
    client: &reqwest::Client,
) -> Result<(), String> {
    let url = format!("{}/verify", base_url);
    let response = client
        .post(&url)
        .body(json!({"data": "abcdefg"}).to_string())
        .send()
        .await
        .map_err(|_| "Failed to send request")?;
    if response.status() != 400 {
        return Err("Expected 400 Bad Request status code from verificaton".to_string());
    }
    let body = response
        .text()
        .await
        .map_err(|_| "Failed to receive response with body from verification")?;
    if body != "missing signature" {
        return Err("Expected missing signature".to_string());
    }

    Ok(())
}
