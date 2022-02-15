use serde_json::{json, Value};

/// Errors if
/// * no body is received
/// * the body is not a valid JSON
/// * the body as JSON is not an Object on the first level
/// * all first level values for the Object are not Strings
pub async fn test_encrypt(
    base_url: &str,
    client: &reqwest::Client,
    base_data: &Value,
) -> Result<Value, String> {
    let url = format!("{}/encrypt", base_url);
    let response = client
        .get(&url)
        .body(base_data.to_string())
        .send()
        .await
        .map_err(|_| "Failed to send request")?;
    let body = response
        .text()
        .await
        .map_err(|_| "Failed to receive response with body from encryption")?;
    let value: Value =
        serde_json::from_str(&body).map_err(|_| "Malformed JSON response in encryption")?;
    if value
        .as_object()
        .ok_or("JSON response is not Object in encryption")?
        .values()
        .all(|v| v.is_string())
    {
        Ok(value)
    } else {
        Err("JSON response's object does not have all fields as String in encryption".to_string())
    }
}

/// Errors if
/// * no body is received
/// * the body is not a valid JSON
/// * the body as JSON is not the same as the base_data
pub async fn test_decrypt(
    base_url: &str,
    client: &reqwest::Client,
    encrypted_data: &Value,
    base_data: &Value,
) -> Result<(), String> {
    let url = format!("{}/decrypt", base_url);
    let response = client
        .get(&url)
        .body(encrypted_data.to_string())
        .send()
        .await
        .unwrap();
    let body = response
        .text()
        .await
        .map_err(|_| "Failed to receive response with body from decryption")?;
    let value: Value =
        serde_json::from_str(&body).map_err(|_| "Malformed JSON response in decryption")?;
    if value == *base_data {
        Ok(())
    } else {
        Err("JSON response is not equal to base data in decryption".to_string())
    }
}

/// Panics if
/// * no body is received
/// * the body is not a valid JSON
/// * the body as JSON is missing the `signature` field
/// * the `signature` field is not a string
pub async fn test_signature(
    base_url: &str,
    client: &reqwest::Client,
    base_data: &Value,
) -> Result<String, String> {
    let url = format!("{}/sign", base_url);
    let response = client
        .get(&url)
        .body(base_data.to_string())
        .send()
        .await
        .map_err(|_| "Failed to receive response.")?;
    let body = response
        .text()
        .await
        .map_err(|_| "Failed to receive response with body from signature")?;
    Ok(serde_json::from_str::<Value>(&body)
        .expect("Malformed JSON response in signature")
        .get("signature")
        .ok_or("Missing signature field on JSON response in signature")?
        .as_str()
        .ok_or("Signature field is not a string in signature")?
        .to_string())
}

/// Errors if
/// * response is not received
/// * response status is not 204 No Content
pub async fn test_verification(
    base_url: &str,
    client: &reqwest::Client,
    encrypted_data: &Value,
    signature: &str,
) -> Result<(), String> {
    let url = format!("{}/verify", base_url);
    let response = client
        .get(&url)
        .body(
            json! ({
                "data": encrypted_data,
                "signature": signature,
            })
            .to_string(),
        )
        .send()
        .await
        .map_err(|_| "Failed to receive response.")?;

    if response.status() == 204 {
        Ok(())
    } else {
        Err("Verification failed".to_string())
    }
}
