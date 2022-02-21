use crypto_hash::{digest, Algorithm};
use rand::rngs::OsRng;
use rsa::pkcs8::{FromPrivateKey, FromPublicKey, ToPrivateKey, ToPublicKey};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

/// Generate a new RSA 2048 bitkey pair.
fn generate_keys(rng: &mut OsRng) -> (RsaPublicKey, RsaPrivateKey) {
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);
    (pub_key, priv_key)
}

/// Takes paths to the private and public key files. If they do not exist and contain valid key pairs, then a key pair is generated with `generate_keys`
/// and the keys are written to the files. Returns either the loaded or generated key pair.
pub fn load_keys<T: AsRef<Path> + Copy, S: AsRef<Path> + Copy>(
    public_file: T,
    private_file: S,
    rng: &mut OsRng,
) -> (RsaPublicKey, RsaPrivateKey) {
    if let (Some(public), Some(private)) = (
        fs::read_to_string(public_file)
            .as_ref()
            .map(|data| RsaPublicKey::from_public_key_pem(data).ok())
            .ok()
            .flatten(),
        fs::read_to_string(private_file)
            .as_ref()
            .map(|data| RsaPrivateKey::from_pkcs8_pem(data).ok())
            .ok()
            .flatten(),
    ) {
        (public, private)
    } else {
        let (public, private) = generate_keys(rng);
        fs::write(
            public_file,
            public
                .to_public_key_pem()
                .expect("failed to serialize public key"),
        )
        .expect("failed to write public key");
        let private_pem = private
            .to_pkcs8_pem()
            .expect("failed to serialize private key");
        fs::write(private_file, private_pem.as_bytes()).expect("failed to write private key");
        (public, private)
    }
}

/// Encrypt a slice of bytes using the public key.
fn encrypt_pub_slice(pub_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>, String> {
    Ok(pub_key
        .encrypt(&mut OsRng, PaddingScheme::new_pkcs1v15_encrypt(), data)
        .map_err(|_| "failed to encrypt")?)
}

/// Encrypt and then base64 encode a string using the public key.
fn encrypt_pub_string(pub_key: &RsaPublicKey, data: &str) -> Result<String, String> {
    Ok(base64::encode(encrypt_pub_slice(pub_key, data.as_bytes())?))
}

/// Decrypt a slice of bytes using the private key.
fn decrypt_private_slice(
    priv_key: &RsaPrivateKey,
    data: &[u8],
) -> Result<Vec<u8>, rsa::errors::Error> {
    priv_key.decrypt(PaddingScheme::new_pkcs1v15_encrypt(), data)
}

/// Decrypt a base64 encoded string using the private key.
fn decrypt_private_string(priv_key: &RsaPrivateKey, data: &str) -> Result<String, String> {
    let data = base64::decode(data).map_err(|_| "failed to decode base64")?;
    Ok(
        String::from_utf8(decrypt_private_slice(priv_key, &data).map_err(|_| "failed to decrypt")?)
            .map_err(|_| "invalid utf8 string")?,
    )
}

/// Takes a serde_json::Value and encrypts it using the public key on every key specified by the Config (/config endpoint).
pub fn detect_and_encrypt(
    payload: &Value,
    public_key: &RsaPublicKey,
    fields: &[String],
) -> Result<Value, String> {
    let mut data = payload.clone();
    match &mut data {
        Value::Array(vec) => {
            for entry in vec.iter_mut() {
                *entry = detect_and_encrypt(entry, public_key, fields)?;
            }
        }
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if fields.contains(&key.to_string()) {
                    *value = json!(encrypt_pub_string(public_key, &value.to_string())?);
                } else {
                    // the value is not to be encrypted, if the value is an array or object, recurse
                    *value = detect_and_encrypt(value, public_key, fields)?;
                }
            }
        }
        _ => {}
    }
    Ok(data)
}

/// Recursively traverses a serde_json::Value and decrypts all strings using the private key.
pub fn detect_and_decrypt(data: &Value, private_key: &RsaPrivateKey) -> Value {
    let mut data = data.clone();
    if let Some(map) = data.as_object_mut() {
        for entry in map.values_mut() {
            if let Value::String(string) = entry {
                // Reasonable assumption that the encrypted string will not contain encrypted fields after decryption.
                // (not encrypted twice)
                if let Some(valid_decrypted) = decrypt_private_string(private_key, string)
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                {
                    *entry = valid_decrypted;
                }
            } else if let Value::Array(array) = entry {
                for entry in array.iter_mut() {
                    *entry = detect_and_decrypt(entry, private_key);
                }
            } else if let Value::Object(_object) = entry {
                *entry = detect_and_decrypt(entry, private_key);
            }
        }
    }
    data
}

/// Get a signature for a serde_json::Value using the private key.
/// Hashes the value using SHA256 and then signs the hash using the private key.
pub fn get_signature(payload: &Value, private_key: &RsaPrivateKey) -> String {
    base64::encode(
        private_key
            .sign(
                PaddingScheme::new_pkcs1v15_sign(None),
                &digest(Algorithm::SHA256, payload.to_string().as_bytes()),
            )
            // padding scheme guaranteed to be valid
            .unwrap(),
    )
}

/// Verify a signature for a serde_json::Value using the public key. Decrypts using the private key any encrypted fields.
/// Requires a signature and a data object.
pub fn get_verification(
    payload: &Value,
    public_key: &RsaPublicKey,
    private_key: &RsaPrivateKey,
) -> Result<bool, String> {
    let signature = payload
        .get("signature")
        .ok_or("missing signature")?
        .as_str()
        .ok_or("signature must be a string")?;
    let signature = base64::decode(signature).map_err(|_| "failed to decode signature")?;
    Ok(public_key
        .verify(
            PaddingScheme::new_pkcs1v15_sign(None),
            &digest(
                Algorithm::SHA256,
                detect_and_decrypt(payload.get("data").ok_or("missing payload")?, private_key)
                    .to_string()
                    .as_bytes(),
            ),
            &signature,
        )
        .is_ok())
}

/// Accept a Value containing the fields to encrypt. Returns the vector containing those fields.
pub fn get_config(payload: &Value) -> Result<Vec<String>, String> {
    Ok(payload
        .get("fieldsToEncrypt")
        .ok_or("missing fieldsToEncrypt")?
        .as_array()
        .ok_or("fieldsToEncrypt must be an array")?
        .iter()
        .map(|x| {
            x.as_str()
                .ok_or("fieldsToEncrypt must be a string")
                .map(|x| x.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?)
}
