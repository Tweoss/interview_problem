# Building and Running
`cargo run`

# Instructions

1. Has two endpoints /encrypt and /decrypt. Each endpoint should take a JSON payload.
2. The server’s key(s) should be generated on first start and written to disk, and should be read in on subsequent startups.
3. Use the key from step 2 to implement encryption and decryption on the `/encrypt` and `/decrypt` endpoints respectively
   ○ `/encrypt` should encrypt every value in the object (at a depth of 1), returning the encrypted payload as JSON
   ○ For example:
     {
         “foo”: “foobar”,
         “bar”: {
         “isBar”: true
         }
     }
   ○ Would become:
     {
         “foo”: “some_encrypted_string”, “bar”: “some_encrypted_string”
     }
   ○ `/decrypt` should detect encrypted strings and decrypt them, returning the decrypted payload as JSON
4. Create a `/sign` endpoint which takes a JSON payload and computes a cryptographic signature for the plaintext payload. The signature is then sent in a JSON response.
5. Create a `/verify` endpoint, which takes a JSON payload of form:
 {
     “signature”: <COMPUTED_SIGNATURE>, “data”: { ... }
 }
   ○ Where data can be any JSON object and can contain encrypted fields
   ○ Any encrypted fields in the data should be decrypted before computing its signature is recomputed. If this signature matches the given signature the response should be 204, else 400.

