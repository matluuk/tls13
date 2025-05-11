# TLS 1.3 protocol implementation in Rust

This is my take on educational TLS 1.3 protocol excercise https://github.com/ouspg/tls13tutorial/ for University of Oulu course IC00AJ73 Cyber Security II: Cloud and Network Security 2025. My implementation is able to perform TLS 1.3 handshake and application data encryption and decryption. It covers server finished message verification and servers signature validation, but it doesn't verify certificates. The handshake is successfull with ciphersuite `TLS_CHACHA20_POLY1305_SHA256`

# Demonstration

I have tested the implementation against openssl s_server:

Keygen
```bash
openssl genpkey -algorithm ED25519 -out server_key.pem
openssl req -new -key server_key.pem -out server_cert.csr -subj "/CN=localhost"
openssl req -x509 -key server_key.pem -in server_cert.csr -out server_cert.pem -days 365
openssl x509 -in server_cert.pem -text -noout
```

```bash
openssl s_server -accept 4433 -tls1_3 -key server_key.pem -cert server_cert.pem -sigalgs ed25519 -groups x25519 -no_resumption_on_reneg -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -msg -debug -trace -state -security_debug -security_debug_verbose
```

Now the tls client can be run

```
RUST_LOG="info" cargo run localhost:4433
```

The client sends hardcoded http request to server and waits 5 seconds before trying to read responce.
`"GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n"`


Logs from successfull connection:

openssl server
```bash
openssl s_server -accept 4433 -tls1_3 -key server_key.pem -cert server_cert.pem -sigalgs ed25519 -groups x25519 -ciphersuites TLS_CHACHA20_POLY1305_SHA
256
Using default temp DH parameters
ACCEPT
-----BEGIN SSL SESSION PARAMETERS-----
MHMCAQECAgMEBAITAwQgxtnGU75Q/43lLhE7f5D/lv8TpKq+9JBirs+npwJz0oIE
IO0fIIedLZMeljLC0UeTi1nYL6OTw5N6cWoUhX163fU+oQYCBGghBJWiBAICHCCk
BgQEAQAAAK4HAgUAq3L8DbMDAgEd
-----END SSL SESSION PARAMETERS-----
Shared ciphers:TLS_CHACHA20_POLY1305_SHA256
Signature Algorithms: Ed25519
Shared Signature Algorithms: Ed25519
Supported groups: x25519
Shared groups: x25519
CIPHER is TLS_CHACHA20_POLY1305_SHA256
Secure Renegotiation IS NOT supported
GET / HTTP/1.1
Host: localhost
Connection: close

asd
ERROR
8084810A417F0000:error:0A000126:SSL routines:ssl3_read_n:unexpected eof while reading:ssl/record/rec_layer_s3.c:308:
shutting down SSL
CONNECTION CLOSED
```

Client
```scala
RUST_LOG="info" cargo run localhost:4433
   Compiling tls13tutorial v0.1.0 (/home/user/CyberSecurityII/tls1-3/tls13)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 3.18s
     Running `target/debug/tls13tutorial 'localhost:4433'`
[INFO  tls13tutorial] Successfully connected to the server 'localhost:4433'.
[INFO  tls13tutorial] Sending ClientHello as follows...
    
ClientHello, Length=158
  client_version=0x303
  random (len=32): 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
  session_id (len=32): 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
  cipher_suites (len=1)
    [0x13, 0x03] TLS_CHACHA20_POLY1305_SHA256
  compression_methods (len=1): 00
  extensions (len=83)
    extension_type=supported_versions(43), length=3
      data: 020304
    extension_type=server_name(0), length=14
      data: 000C0000096C6F63616C686F7374
    extension_type=supported_groups(10), length=4
      data: 0002001D
    extension_type=signature_algorithms(13), length=4
      data: 00020807
    extension_type=key_share(51), length=38
      data: 0024001D00208F40C5ADB68F25624AE5B214EA767A6EC94D829D3D7B5E1AD1BA6F3E2138285F

[INFO  tls13tutorial] The handshake request has been sent...
[WARN  tls13tutorial] TCP read blocking for more than 0.5 seconds...force return.
[INFO  tls13tutorial] Response TLS Record received!
[INFO  tls13tutorial] Response TLS Record received!
[INFO  tls13tutorial] Response TLS Record received!
[INFO  tls13tutorial] Response TLS Record received!
[INFO  tls13tutorial] Response TLS Record received!
[INFO  tls13tutorial] Response TLS Record received!
[INFO  tls13tutorial] ServerHello message received
[INFO  tls13tutorial] Found server's X25519 key share: 2E7E14A6DCBB7D8B3B1B2CC5A4A39EA26709065BB3A21D1663DEF7A9F425155F
[INFO  tls13tutorial] Handshake keys derived successfully
[INFO  tls13tutorial] Received ChangeCipherSpec message (ignored in TLS 1.3)
[INFO  tls13tutorial] Received EncryptedExtensions message
[INFO  tls13tutorial] Empty EncryptedExtensions received
[INFO  tls13tutorial] Received Certificate message
[INFO  tls13tutorial::certificate] Validating certificate chain with 1 certificates against hostname: localhost
[INFO  tls13tutorial::certificate] Certificate #0 details:
[INFO  tls13tutorial::certificate]   Version: X.509v2
[INFO  tls13tutorial::certificate]   Serial Number: 283285799878223556499282819846364792198606915509
[INFO  tls13tutorial::certificate]   Signature Algorithm: ObjectIdentifier([1, 3, 101, 112])
[INFO  tls13tutorial::certificate]   Issuer:
[INFO  tls13tutorial::certificate]     CN: localhost
[INFO  tls13tutorial::certificate]   Extensions:
[INFO  tls13tutorial::certificate]     subjectKeyIdentifier: 22 bytes
[INFO  tls13tutorial::certificate]     authorityKeyIdentifier: 24 bytes
[INFO  tls13tutorial::certificate]     basicConstraints: 5 bytes (critical)
[INFO  tls13tutorial::certificate] Certificate validity: 2025-05-11 20:07:40.0 +00:00:00 to 2026-05-11 20:07:40.0 +00:00:00
[WARN  tls13tutorial::certificate] Certificate chain validation not fully implemented yet
[INFO  tls13tutorial] Received CertificateVerify message
[INFO  tls13tutorial::certificate] Ed25519 signature verified successfully
[INFO  tls13tutorial] Received Finished message
[INFO  tls13tutorial] Server Finished message verified successfully
[INFO  tls13tutorial] Sending ChangeCipherSpec for compatibility
[INFO  tls13tutorial] Sending Client Finished message
[INFO  tls13tutorial] Handshake completed
[INFO  tls13tutorial] Starting application data exchange.
[INFO  tls13tutorial] Sent HTTP request:
    GET / HTTP/1.1
    Host: localhost
    Connection: close
    
    
[INFO  tls13tutorial] Waiting for 5s to receive the response...
[WARN  tls13tutorial] TCP read blocking for more than 0.5 seconds...force return.
[INFO  tls13tutorial] Response TLS Record received!
[INFO  tls13tutorial] Response TLS Record received!
[INFO  tls13tutorial] Response TLS Record received!
[WARN  tls13tutorial] Received inner Handshake message (type 22) within ApplicationData record. Length: 217. Content: 040000D500001C200CAC573408000000000000000000C0E26A4D334F1F70DD69B16872091A0AA2FF4AFB03DF1C2334519FAD6C0ED03B0D326965DD3D1486D41CABEC9EFC34235612E2FBE139E8687F54D0C7A3A1BBA51F8027798D8DD23E0B0A0003EB84E5A80BDF60FA04A0A6785AA4F9DB8E17EDB73FEC20E0110D03D4DC44B37C3D2665CB47D9160EC68DBFCB6B5F7B114E25536E6984A0B2B06FB23CA0587628A2816A31D3AEFFF15F3768BE8099240BD923B820A9E02AD12B3ED7DFD1BD9F1747C3DE77EBBA996F16D9303DDFD1E624A5396B1F6F0000. Discarding and continuing to look for application data.
[WARN  tls13tutorial] Received inner Handshake message (type 22) within ApplicationData record. Length: 217. Content: 040000D500001C206786696708000000000000000100C0E26A4D334F1F70DD69B16872091A0AA2BD5A5C93B3172BD94F01D79D62BEA8635526B0854F07D3F9B8F8ECD47C9215508B06FAD098DFF531BD1CB85CE84C97B074086F2062289CA1F7E853C3117ABECCB0A7D9DA3031CF9AB6CD84F26D5DAE76289BCAD1802F98F518F37E640B406B47B001C1FF49BA6F14D24ECB758768E21BAD950DA713D85D48CD5A9F9DEAA20EFB4D891BBF44F6FD4D3F9BBFA1F4D053AAE97D5532BB227462B3C673AD17DE980CD04BE5B28F5E5F4066A7FAE28D5164940000. Discarding and continuing to look for application data.
[INFO  tls13tutorial] Received inner ApplicationData (type 23), payload length 4
[INFO  tls13tutorial] Received application data (processed): asd
    
[INFO  tls13tutorial] Received response:
    asd
```

# Implementation details

## Parser
Parser improvements in `src/parser.rs`:
- Check taht there is enough data for request
- Added bound check in `get_bytes()`
- Added debug functions for getting remaining data in deque `remaining_data()` and `remaining_data_hex`

Implemented byte parsing for tls extensions `src/extensions.rs`:
- 0 - ServerName
- 10 - SupportedGroups
- 13 - SignatureAlgorithms
- 51 - KeyShareServerHello or KeyShareClientHello
- 43 - SupportedVersions 
- 45 - PskKeyExchangeModes

## Certificate handling
Certificate handling `src/certificate.rs`:
Following crates are used for certificate handling: `rasn` and `rasn-pkix` are used for converting ASN.1 DER-encoded certificates to Rust structures, `ed25519-dalek` have been used for signature verification, `time` is used for handling time in certificate verification.
- Implemented server's signature verification using transcript hash and certificate `verify_certificate_signature()`
- ed25519 public key extraction `extract_ed25519_public_key()` using `rasn` and `rasn-pkix`
- Certificate validation have been tried using `webpki` `webpki-roots`. This doesn't work properly.

## Trabscript hash
Transcript hash calculation is managed by the `TranscriptManager` struct in `src/main.rs`.

-   **Initialization**: A new `TranscriptManager` starts with an empty list of messages and an empty hash.
-   **Updating**: When a handshake message is processed, its raw byte representation is added to an internal list of messages. The `TranscriptManager` then recalculates the transcript hash by creating a new SHA-256 hasher, feeding it *all* handshake messages received or sent so far (in order), and finalizing the hash.
-   **Usage**: The current transcript hash is retrieved using `get_current_hash()` and is used in key derivation (for handshake and application keys) and for verifying the server's `Finished` message and creating the client's `Finished` message.


## handshake keys
The functions for deriving and using application keys are implemented to secure data exchanged after the handshake.


## Application keys

The `ApplicationKeys` struct in `src/main.rs` stores the symmetric keys and IVs used for encrypting and decrypting application data after the TLS handshake is complete. It also maintains separate sequence numbers for client and server data. The struct is pretty similar to the provided almost complete handshake keys struct.

Implementation details:
-   **Structure**: It holds `client_app_key`, `client_app_iv`, `server_app_key`, and `server_app_iv`, all derived for the `CHACHA20_POLY1305_SHA256` cipher suite. It also includes `client_seq_num` and `server_seq_num` to track record sequence numbers for AEAD nonce construction.
-   **Derivation**: The `ApplicationKeys::new()` method is responsible for deriving these keys. It takes the `HandshakeKeys` (which contain the Diffie-Hellman shared secret) and the final transcript hash as input.
    -   It follows the TLS 1.3 key schedule:
        1.  Re-derives the `early_secret` (as PSK is not used, it's derived from a salt of zeros).
        2.  Derives a `derived_secret` from the `early_secret`.
        3.  Extracts the `handshake_secret` using the `derived_secret` and the DH `shared_secret`.
        4.  Derives another `derived_secret` (labeled "derived") from the `handshake_secret`.
        5.  Extracts the `master_secret` using this new `derived_secret` and an empty key material (since there's no PSK).
        6.  From the `master_secret` and the `transcript_hash`, it derives `client_application_traffic_secret_0` and `server_application_traffic_secret_0`.
        7.  Finally, the actual `client_app_key`/`iv` and `server_app_key`/`iv` are derived from their respective traffic secrets using HKDF-Expand with "key" and "iv" labels.
-   **Usage**: Instances of `ApplicationKeys` are used by `encrypt_client_application_data` and `decrypt_server_application_data` methods to secure the application data phase.

## server finished message verification
The server's `Finished` message is the first message authenticated with the newly negotiated keys. It confirms that the key exchange and authentication were successful.

My implementation details:
-   The `verify_server_finished` function in `src/main.rs` is responsible for this.
-   It calculates the expected `verify_data` by computing an HMAC (using SHA-256) over the transcript hash of all handshake messages up to (but not including) the server's `Finished` message.
-   The key used for this HMAC is the `server_finished_key`, which is derived from the `server_handshake_traffic_secret` (itself derived from the `handshake_secret`).
-   The `server_handshake_traffic_secret` is obtained using the `derive_secret` function with the label "s hs traffic" and the `handshake_secret`. The `server_finished_key` is then derived from this traffic secret using the `derive_secret` function with the label "finished".
-   The calculated `verify_data` is then compared with the `verify_data` received in the server's `Finished` message. A mismatch indicates a handshake failure.

# Error handling

The project utilizes Rust's `Result<T, E>` enum for error management.
-   **I/O Operations**: Standard `std::io::Error` is handled for network communication, including timeouts and specific handling for non-blocking operations.
-   **Protocol Logic**: Custom `String` errors are generally used for issues arising from TLS protocol parsing, cryptographic failures (e.g., decryption, signature verification), or unexpected message sequences. These errors are typically propagated, and critical failures lead to termination.
-   **Alerts**: Received TLS Alert messages are processed. Fatal alerts, as per TLS 1.3 specification, will terminate the connection.
-   **Logging**: The `log` crate is employed to output detailed error and warning messages
-   **Resilience**: In some cases, such as during application data reception, the client attempts to recover from non-fatal errors (e.g., a single undecipherable record) by logging the issue and continuing to process further data, rather than immediately terminating.
-   **Assertions**: `expect()` is used for conditions that should logically never fail, treating such occurrences as critical program errors.

# Unit testing:

Unittests can be run with
```shell
cargo test
```

There are some unittests for some modules. The unittests are mainly created by LLM:s and only briefly checked for most obvious mistakes. Current tests primarily cover aspects of:
`src/extensions.rs`: serialization and deserialization of various extension types
`src/certificates.rs`: public key extraction
`src/main.rs`: transcript hash calculation and common name extraction

# Fuzzing

Fuzzing for this project is not performed

# LLM usage

Throughout the development of this TLS 1.3 client, Large Language Models (LLMs), including GitHub Copilot, were utilized as an assistive tool. Their use included:
-   Generating boilerplate code and initial implementations for some protocol structures and cryptographic operations.
-   Assisting in debugging by suggesting potential causes for errors and offering solutions.
-   Providing explanations for complex aspects of the TLS 1.3 protocol and cryptographic primitives.
-   Helping to draft documentation and comments.
-   Generating initial versions of unit tests for various modules.

All LLM-generated code and suggestions were reviewed, tested, and modified as necessary to ensure correctness and fit within the project's architecture and requirements. The final implementation and logic are the result of this iterative process.