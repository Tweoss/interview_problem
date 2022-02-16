# Build, Run, Test
To build the server and the testing binary then execute both, run the shell script `run_test.sh`.
```bash
./run_test.sh
```

# General Details
The `solution` folder contains the server. 
`main.rs` contains the boilerplate for starting the server. Keys are generated or loaded here, and the threads for handling requests are spawned here. 
`crypto.rs` contains the implementation of the instructions on serde_json Values. 
`routes.rs` contains the handlers for the server that call the crypto functions. 

The `testing` folder contains non-exhaustive testing code for the server. 
`main.rs` runs the checking code.
`checks.rs` contains the checks for each endpoint. 
`negative_checks.rs` contains checks for each endpoint that should fail.

# Original Instructions

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

