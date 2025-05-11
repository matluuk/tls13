#![allow(dead_code)]
use log::{debug, error, info, warn};
#[cfg(not(debug_assertions))]
use rand::rngs::OsRng;
use std::collections::VecDeque;
use std::io::{self, Read as SocketRead, Write as SocketWrite};
use std::net::TcpStream;
use std::thread::sleep;
use std::time::Duration;
use tls13tutorial::alert::Alert;
use tls13tutorial::display::to_hex;
use tls13tutorial::extensions::{
    ByteSerializable, Extension, ExtensionData, ExtensionOrigin, ExtensionType,
    KeyShareClientHello, KeyShareEntry, NameType, NamedGroup, NamedGroupList, ServerName,
    ServerNameList, SignatureScheme, SupportedSignatureAlgorithms, SupportedVersions, VersionKind,
};
use tls13tutorial::handshake::{
    cipher_suites, ClientHello, Handshake, HandshakeMessage, HandshakeType,
    Random, TLS_VERSION_1_3, TLS_VERSION_COMPATIBILITY,
};
use tls13tutorial::parser::ByteParser;
use tls13tutorial::tls_record::{ContentType, TLSRecord};

// Import our new module
mod certificate;

// Cryptographic libraries
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

const DEBUGGING_EPHEMERAL_SECRET: [u8; 32] = [
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Key calculation and resulting keys, includes initial random values for `ClientHello`
/// Check section about [KeySchedule](https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)

/// Maintains the transcript hash state throughout the TLS 1.3 handshake
struct TranscriptManager {
    messages: Vec<Vec<u8>>,
    current_hash: Vec<u8>,
}

impl TranscriptManager {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
            current_hash: Vec::new(),
        }
    }

    /// Add a new handshake message to the transcript and update the hash
    fn update(&mut self, message: &[u8]) {
        // Debug: Print the message bytes being added
        debug!("Adding message to transcript: {}", to_hex(message));

        // Store the raw message
        self.messages.push(message.to_vec());

        // Recalculate the hash with all messages so far
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        for msg in &self.messages {
            hasher.update(msg);
        }
        self.current_hash = hasher.finalize().to_vec();

        debug!("Updated transcript hash: {}", to_hex(&self.current_hash));
    }

    /// Get the current transcript hash
    fn get_current_hash(&self) -> &[u8] {
        &self.current_hash
    }

    /// Get all stored handshake messages
    fn get_messages(&self) -> &[Vec<u8>] {
        &self.messages
    }
}

struct HandshakeKeys {
    random_seed: Random,
    session_id: Random,
    // WARNING: we should use single-use `EphemeralSecret` for security in real systems
    dh_client_ephemeral_secret: StaticSecret,
    dh_client_public: PublicKey,
    dh_server_public: PublicKey,
    dh_shared_secret: Option<SharedSecret>, // Instanced later
    client_hs_key: Vec<u8>,
    client_hs_iv: Vec<u8>,
    client_hs_finished_key: Vec<u8>,
    client_seq_num: u64,
    server_hs_key: Vec<u8>,
    server_hs_iv: Vec<u8>,
    server_hs_finished_key: Vec<u8>,
    server_seq_num: u64,
}
impl HandshakeKeys {
    #[must_use]
    fn new() -> Self {
        // Generate 32 bytes of random data as key length is 32 bytes in SHA-256
        // let seed_random = rand::random::<[u8; 32]>();
        // FIXME use random data instead of hardcoded seed
        // Hardcoded value has been used for debugging purposes
        let random_seed = DEBUGGING_EPHEMERAL_SECRET;
        // let random_session_id = rand::random::<[u8; 32]>();
        let session_id = random_seed;
        // Generate a new Elliptic Curve Diffie-Hellman public-private key pair (X25519)
        let (dh_client_ephemeral_secret, dh_client_public);
        #[cfg(not(debug_assertions))]
        {
            dh_client_ephemeral_secret = StaticSecret::random_from_rng(OsRng);
            dh_client_public = PublicKey::from(&dh_client_ephemeral_secret);
        }
        #[cfg(debug_assertions)]
        {
            dh_client_ephemeral_secret = StaticSecret::from(DEBUGGING_EPHEMERAL_SECRET);
            dh_client_public = PublicKey::from(&dh_client_ephemeral_secret);
        }

        Self {
            random_seed,
            session_id,
            dh_client_ephemeral_secret,
            dh_client_public,
            dh_server_public: PublicKey::from([0u8; 32]),
            dh_shared_secret: None,
            client_hs_key: vec![0u8; 32],
            client_hs_iv: vec![0u8; 12],
            client_hs_finished_key: vec![0u8; 32],
            client_seq_num: 0,
            server_hs_key: vec![0u8; 32],
            server_hs_iv: vec![0u8; 12],
            server_hs_finished_key: vec![0u8; 32],
            server_seq_num: 0,
        }
    }
    /// Update the keys based on handshake messages
    /// Specific for SHA256 hash function
    /// See especially Section 7. in the standard
    /// This function works correctly for the initial key calculation, to finish the handshake
    /// you need to also other keys later on following the same idea.
    fn key_schedule(&mut self, transcript_hash: &[u8]) {
        // Calculate the shared secret
        self.dh_shared_secret = Some(
            self.dh_client_ephemeral_secret
                .diffie_hellman(&self.dh_server_public),
        );
        // Early secret - we don't implement PSK, so need to use empty arrays
        let (early_secret, _hk) = Hkdf::<Sha256>::extract(Some(&[0u8; 32]), &[0u8; 32]);
        let sha256_empty = Sha256::digest([]);
        let derived_secret = Self::derive_secret(&early_secret, b"derived", &sha256_empty, 32);
        // Handshake secrets with Key & IV pairs
        let (handshake_secret, _hk) = Hkdf::<Sha256>::extract(
            Some(&derived_secret),
            self.dh_shared_secret.as_ref().unwrap().as_bytes(),
        );
        let client_hs_traffic_secret =
            Self::derive_secret(&handshake_secret, b"c hs traffic", transcript_hash, 32);
        self.client_hs_key = Self::derive_secret(&client_hs_traffic_secret, b"key", &[], 32);
        self.client_hs_iv = Self::derive_secret(&client_hs_traffic_secret, b"iv", &[], 12);
        self.client_hs_finished_key =
            Self::derive_secret(&client_hs_traffic_secret, b"finished", &[], 32);
        let server_hs_traffic_secret =
            Self::derive_secret(&handshake_secret, b"s hs traffic", transcript_hash, 32);
        self.server_hs_key = Self::derive_secret(&server_hs_traffic_secret, b"key", &[], 32);
        self.server_hs_iv = Self::derive_secret(&server_hs_traffic_secret, b"iv", &[], 12);
        self.server_hs_finished_key =
            Self::derive_secret(&server_hs_traffic_secret, b"finished", &[], 32);
        // Print all the keys as hex strings
        debug!(
            "Shared secret: {}",
            to_hex(self.dh_shared_secret.as_ref().unwrap().as_bytes())
        );
        debug!("Early secret: {}", to_hex(&early_secret));
        debug!("Derived secret: {}", to_hex(&derived_secret));
        debug!("Handshake secret: {}", to_hex(&handshake_secret));
        debug!(
            "Client handshake traffic secret: {}",
            to_hex(&client_hs_traffic_secret)
        );
        debug!("Client handshake key: {}", to_hex(&self.client_hs_key));
        debug!("Client handshake IV: {}", to_hex(&self.client_hs_iv));
        debug!(
            "Client handshake finished key: {}",
            to_hex(&self.client_hs_finished_key)
        );
        debug!(
            "Server handshake traffic secret: {}",
            to_hex(&server_hs_traffic_secret)
        );
        debug!("Server handshake key: {}", to_hex(&self.server_hs_key));
        debug!("Server handshake IV: {}", to_hex(&self.server_hs_iv));
        debug!(
            "Server handshake finished key: {}",
            to_hex(&self.server_hs_finished_key)
        );
    }
    /// Expand the secret with the label and transcript hash (hash bytes of the combination of messages)
    /// Label format is described in the RFC 8446 section 7.1
    /// FIXME will panic on invalid lengths. Maybe someone notices this with a bit of fuzzing..
    #[must_use]
    fn derive_secret(
        secret: &[u8],
        label: &[u8],
        transcript_hash: &[u8],
        length: usize,
    ) -> Vec<u8> {
        let mut hkdf_label = Vec::new();
        hkdf_label.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
        // All the labels are ASCII strings, prepend with "tls13 "
        let mut combined_label = b"tls13 ".to_vec();
        combined_label.extend_from_slice(label);
        hkdf_label.extend_from_slice(&u8::try_from(combined_label.len()).unwrap().to_be_bytes());
        hkdf_label.extend_from_slice(&combined_label);
        hkdf_label.extend_from_slice(&u8::try_from(transcript_hash.len()).unwrap().to_be_bytes());
        hkdf_label.extend_from_slice(transcript_hash);
        let hk = Hkdf::<Sha256>::from_prk(secret).expect("Failed to create HKDF from PRK");
        let mut okm = vec![0u8; length];
        hk.expand(&hkdf_label, &mut okm)
            .expect("Failed to expand the secret");
        okm
    }

    /// Decrypt TLS 1.3 handshake records encrypted with ChaCha20-Poly1305
    ///
    /// According to RFC 8446, the nonce is formed by XORing the sequence number with the IV.
    /// The sequence counter is incremented after each record is processed.
    fn decrypt_server_handshake(
        &mut self,
        encrypted_data: &[u8],
        record_type: ContentType,
        record_version: u16,
        record_length: u16,
    ) -> Result<Vec<u8>, String> {
        // ChaCha20-Poly1305 authentication tag is 16 bytes
        if encrypted_data.len() < 16 {
            return Err("Encrypted data is too short for ChaCha20-Poly1305".to_string());
        }

        // Split the data into ciphertext and auth tag
        let ciphertext = &encrypted_data[..encrypted_data.len() - 16];
        let auth_tag = &encrypted_data[encrypted_data.len() - 16..];

        debug!("Ciphertext length: {}", ciphertext.len());
        debug!("Auth tag: {}", to_hex(auth_tag));

        // Initialize the ChaCha20-Poly1305 cipher with the server handshake key
        let cipher = match ChaCha20Poly1305::new_from_slice(&self.server_hs_key) {
            Ok(c) => c,
            Err(e) => return Err(format!("Failed to create ChaCha20Poly1305 cipher: {}", e)),
        };

        // Create the nonce by XORing the IV with the sequence number
        // Per TLS 1.3 spec: the 64-bit record sequence number is encoded as an 8-byte big-endian value
        // and padded on the left with zeros to iv_length.
        let mut nonce = [0u8; 12]; // ChaCha20-Poly1305 uses 12-byte nonces
        let seq_bytes = self.server_seq_num.to_be_bytes();

        // Copy the IV first
        nonce.copy_from_slice(&self.server_hs_iv);

        // XOR the last 8 bytes with the sequence number
        for i in 4..12 {
            nonce[i] ^= seq_bytes[i - 4];
        }

        debug!("Using server_hs_key: {}", to_hex(&self.server_hs_key));
        debug!("Using server_hs_iv: {}", to_hex(&self.server_hs_iv));
        debug!("Sequence number: {}", self.server_seq_num);
        debug!("Nonce: {}", to_hex(&nonce));

        // In TLS 1.3, the additional authenticated data (AAD) is the TLS record header (5 bytes)
        let mut aad = vec![record_type as u8];
        aad.extend_from_slice(&record_version.to_be_bytes());
        aad.extend_from_slice(&record_length.to_be_bytes());
        debug!("AAD: {}", to_hex(&aad));

        // Combine ciphertext and auth tag for most AEAD libraries
        let mut ciphertext_with_tag = ciphertext.to_vec();
        ciphertext_with_tag.extend_from_slice(auth_tag);

        // Decrypt the message
        let plaintext = match cipher.decrypt(
            &nonce.into(),
            Payload {
                msg: &ciphertext_with_tag,
                aad: &aad,
            },
        ) {
            Ok(pt) => pt,
            Err(e) => return Err(format!("Decryption failed: {}", e)),
        };

        // Increment the sequence number for next message
        self.server_seq_num += 1;

        debug!(
            "Decryption successful, plaintext length: {}",
            plaintext.len()
        );

        Ok(plaintext)
    }

    /// Encrypt data using client handshake keys with ChaCha20-Poly1305
    fn encrypt_client_handshake(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        // Initialize the ChaCha20-Poly1305 cipher with the client handshake key
        let cipher = match ChaCha20Poly1305::new_from_slice(&self.client_hs_key) {
            Ok(c) => c,
            Err(e) => return Err(format!("Failed to create ChaCha20Poly1305 cipher: {}", e)),
        };

        // Create the nonce by XORing the IV with the sequence number
        let mut nonce = [0u8; 12]; // ChaCha20-Poly1305 uses 12-byte nonces
        let seq_bytes = self.client_seq_num.to_be_bytes();

        // Copy the IV first
        nonce.copy_from_slice(&self.client_hs_iv);

        // XOR the last 8 bytes with the sequence number
        for i in 4..12 {
            nonce[i] ^= seq_bytes[i - 4];
        }

        debug!("Using client_hs_key: {}", to_hex(&self.client_hs_key));
        debug!("Using client_hs_iv: {}", to_hex(&self.client_hs_iv));
        debug!("Sequence number: {}", self.client_seq_num);
        debug!("Nonce: {}", to_hex(&nonce));

        // Calculate record_length for AAD: length of (plaintext_with_inner_type + 16_byte_tag)
        // This is the length that the TLSCiphertext.length field in the AAD will have.
        let record_length_for_aad = u16::try_from(plaintext.len() + 16) // 16 bytes for Poly1305 tag
            .map_err(|_| "Plaintext too long for record length calculation".to_string())?;

        // In TLS 1.3, the additional authenticated data (AAD) is the TLS record header.
        // For encrypted handshake messages, the outer record type is ApplicationData.
        let mut aad = vec![ContentType::ApplicationData as u8];
        aad.extend_from_slice(&TLS_VERSION_COMPATIBILITY.to_be_bytes());
        aad.extend_from_slice(&record_length_for_aad.to_be_bytes());
        debug!("AAD for client handshake encryption: {}", to_hex(&aad));

        // Encrypt the message
        let ciphertext_and_tag = match cipher.encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext, // This is the TLSInnerPlaintext (handshake message + content type byte)
                aad: &aad,
            },
        ) {
            Ok(ct) => ct,
            Err(e) => return Err(format!("Encryption failed: {}", e)),
        };

        // Increment the sequence number for next message
        self.client_seq_num += 1;

        debug!(
            "Client handshake encryption successful, ciphertext length: {}",
            ciphertext_and_tag.len()
        );

        Ok(ciphertext_and_tag)
    }
}

/// Keys used for application data encryption/decryption after the handshake is complete
struct ApplicationKeys {
    client_app_key: Vec<u8>,
    client_app_iv: Vec<u8>,
    client_seq_num: u64,
    server_app_key: Vec<u8>,
    server_app_iv: Vec<u8>,
    server_seq_num: u64,
}

impl ApplicationKeys {
    /// Derive application traffic keys from the handshake secret
    fn new(handshake_keys: &HandshakeKeys, transcript_hash: &[u8]) -> Result<Self, String> {
        // Get the shared secret that was established during the handshake
        let shared_secret = handshake_keys
            .dh_shared_secret
            .as_ref()
            .expect("Shared secret must be established before calculating application keys");

        // Early secret - similar to handshake key calculation
        let (early_secret, _) = Hkdf::<Sha256>::extract(Some(&[0u8; 32]), &[0u8; 32]);

        // Derive secret from early secret
        let sha256_empty = Sha256::digest([]);
        let derived_secret =
            HandshakeKeys::derive_secret(&early_secret, b"derived", &sha256_empty, 32);

        // Extract handshake secret using DH shared secret
        let (handshake_secret, _) =
            Hkdf::<Sha256>::extract(Some(&derived_secret), shared_secret.as_bytes());

        // Derive secret for the master secret calculation
        let derived_secret_for_master =
            HandshakeKeys::derive_secret(&handshake_secret, b"derived", &sha256_empty, 32);

        // Extract the master secret using empty key material
        let (master_secret, _) =
            Hkdf::<Sha256>::extract(Some(&derived_secret_for_master), &[0u8; 32]);

        debug!("Master secret: {}", to_hex(&master_secret));

        // Derive client and server application traffic secrets
        let client_app_traffic_secret =
            HandshakeKeys::derive_secret(&master_secret, b"c ap traffic", transcript_hash, 32);
        let server_app_traffic_secret =
            HandshakeKeys::derive_secret(&master_secret, b"s ap traffic", transcript_hash, 32);

        // Derive application keys and IVs
        let client_app_key =
            HandshakeKeys::derive_secret(&client_app_traffic_secret, b"key", &[], 32);
        let client_app_iv =
            HandshakeKeys::derive_secret(&client_app_traffic_secret, b"iv", &[], 12);
        let server_app_key =
            HandshakeKeys::derive_secret(&server_app_traffic_secret, b"key", &[], 32);
        let server_app_iv =
            HandshakeKeys::derive_secret(&server_app_traffic_secret, b"iv", &[], 12);

        debug!(
            "Client application traffic secret: {}",
            to_hex(&client_app_traffic_secret)
        );
        debug!(
            "Server application traffic secret: {}",
            to_hex(&server_app_traffic_secret)
        );
        debug!("Client application key: {}", to_hex(&client_app_key));
        debug!("Client application IV: {}", to_hex(&client_app_iv));
        debug!("Server application key: {}", to_hex(&server_app_key));
        debug!("Server application IV: {}", to_hex(&server_app_iv));

        Ok(Self {
            client_app_key,
            client_app_iv,
            client_seq_num: 0,
            server_app_key,
            server_app_iv,
            server_seq_num: 0,
        })
    }

    /// Encrypt application data using client keys
    fn encrypt_client_application_data(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        // Initialize ChaCha20-Poly1305 cipher with client application key
        let cipher = match ChaCha20Poly1305::new_from_slice(&self.client_app_key) {
            Ok(c) => c,
            Err(e) => return Err(format!("Failed to create ChaCha20Poly1305 cipher: {}", e)),
        };

        // Create nonce by XORing IV with sequence number
        let mut nonce = [0u8; 12];
        let seq_bytes = self.client_seq_num.to_be_bytes();

        // Copy IV first
        nonce.copy_from_slice(&self.client_app_iv);

        // XOR last 8 bytes with sequence number
        for i in 4..12 {
            nonce[i] ^= seq_bytes[i - 4];
        }

        debug!("Using client_app_key: {}", to_hex(&self.client_app_key));
        debug!("Using client_app_iv: {}", to_hex(&self.client_app_iv));
        debug!("Client app sequence number: {}", self.client_seq_num);
        debug!("Nonce: {}", to_hex(&nonce));

        // In TLS 1.3, the additional authenticated data (AAD) is the TLS record header (5 bytes)
        let record_length = u16::try_from(plaintext.len() + 16).expect("Plaintext too long");
        let mut aad = vec![ContentType::ApplicationData as u8];
        aad.extend_from_slice(&TLS_VERSION_COMPATIBILITY.to_be_bytes());
        aad.extend_from_slice(&record_length.to_be_bytes());
        debug!("AAD: {}", to_hex(&aad));

        // Encrypt the message
        let ciphertext = match cipher.encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        ) {
            Ok(ct) => ct,
            Err(e) => return Err(format!("Encryption failed: {}", e)),
        };

        // Increment sequence number
        self.client_seq_num += 1;

        debug!(
            "Application data encryption successful, ciphertext length: {}",
            ciphertext.len()
        );

        Ok(ciphertext)
    }

    /// Decrypt application data using server keys
    fn decrypt_server_application_data(
        &mut self,
        encrypted_data: &[u8],
        record_type: ContentType,
        record_version: u16,
        record_length: u16,
    ) -> Result<Vec<u8>, String> {
        // ChaCha20-Poly1305 authentication tag is 16 bytes
        if encrypted_data.len() < 16 {
            return Err("Encrypted data is too short for ChaCha20-Poly1305".to_string());
        }

        // Split data into ciphertext and auth tag
        let ciphertext = &encrypted_data[..encrypted_data.len() - 16];
        let auth_tag = &encrypted_data[encrypted_data.len() - 16..];

        // Initialize cipher with server application key
        let cipher = match ChaCha20Poly1305::new_from_slice(&self.server_app_key) {
            Ok(c) => c,
            Err(e) => return Err(format!("Failed to create ChaCha20Poly1305 cipher: {}", e)),
        };

        // Create nonce by XORing IV with sequence number
        let mut nonce = [0u8; 12];
        let seq_bytes = self.server_seq_num.to_be_bytes();

        // Copy IV first
        nonce.copy_from_slice(&self.server_app_iv);

        // XOR last 8 bytes with sequence number
        for i in 4..12 {
            nonce[i] ^= seq_bytes[i - 4];
        }

        debug!("Using server_app_key: {}", to_hex(&self.server_app_key));
        debug!("Using server_app_iv: {}", to_hex(&self.server_app_iv));
        debug!("Server app sequence number: {}", self.server_seq_num);
        debug!("Nonce: {}", to_hex(&nonce));

        // Create AAD from record header
        let mut aad = vec![record_type as u8];
        aad.extend_from_slice(&record_version.to_be_bytes());
        aad.extend_from_slice(&record_length.to_be_bytes());
        debug!("AAD: {}", to_hex(&aad));

        // Combine ciphertext and auth tag
        let mut ciphertext_with_tag = ciphertext.to_vec();
        ciphertext_with_tag.extend_from_slice(auth_tag);

        // Decrypt the message
        let plaintext = match cipher.decrypt(
            &nonce.into(),
            Payload {
                msg: &ciphertext_with_tag,
                aad: &aad,
            },
        ) {
            Ok(pt) => pt,
            Err(e) => return Err(format!("Decryption failed: {}", e)),
        };

        // Increment sequence number
        self.server_seq_num += 1;

        debug!(
            "Application data decryption successful, plaintext length: {}",
            plaintext.len()
        );

        Ok(plaintext)
    }
}

/// Process the data from TCP stream in the chunks of 4096 bytes and
/// read the response data into a buffer in a form of Queue for easier parsing.
fn process_tcp_stream(mut stream: &mut TcpStream) -> io::Result<VecDeque<u8>> {
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    let mut reader = io::BufReader::new(&mut stream);
    let mut buffer: VecDeque<u8> = VecDeque::new();
    let mut chunk = [0; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break, // End of data
            Ok(n) => {
                debug!("Received {n} bytes of data.");
                buffer.extend(&chunk[..n]);
            }
            // Nothing to read and no null termination
            // We don't wait more than 0.5 seconds
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                warn!("TCP read blocking for more than 0.5 seconds...force return.");
                return Ok(buffer);
            }
            Err(e) => {
                error!("Error when reading from the TCP stream: {}", e);
                return Err(e);
            }
        }
    }
    Ok(buffer)
}

/// Main event loop for the TLS 1.3 client implementation
#[allow(clippy::too_many_lines)]
fn main() {
    // Get address as command-line argument, e.g. cargo run cloudflare.com:443
    let args = std::env::args().collect::<Vec<String>>();
    let address = if args.len() > 1 {
        args[1].as_str()
    } else {
        eprintln!("Usage: {} <address:port>", args[0]);
        std::process::exit(1);
    };
    // Creating logger.
    // You can change the level with RUST_LOG environment variable, e.g. RUST_LOG=debug
    env_logger::builder().format_timestamp(None).init();
    // Note: unsafe, not  everything-covering validation for the address
    let Some((hostname, _port)) = address.split_once(':') else {
        error!("Invalid address:port format");
        std::process::exit(1);
    };
    // Create initial random values and keys for the handshake
    let mut handshake_keys = HandshakeKeys::new();
    let mut app_keys: Option<ApplicationKeys> = None;

    let mut transcript_manager = TranscriptManager::new();
    let mut server_certificate: Option<tls13tutorial::handshake::Certificate> = None;
    let mut handshake_complete = false;

    match TcpStream::connect(address) {
        Ok(mut stream) => {
            info!("Successfully connected to the server '{address}'.");

            // Generate the ClientHello message with the help of the data structures
            // Selects the cipher suite and properties
            let client_hello = ClientHello {
                legacy_version: TLS_VERSION_COMPATIBILITY,
                random: handshake_keys.random_seed,
                legacy_session_id: handshake_keys.session_id.into(),
                cipher_suites: vec![cipher_suites::TLS_CHACHA20_POLY1305_SHA256],
                legacy_compression_methods: vec![0],
                extensions: vec![
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::SupportedVersions,
                        extension_data: ExtensionData::SupportedVersions(SupportedVersions {
                            version: VersionKind::Suggested(vec![TLS_VERSION_1_3]),
                        }),
                    },
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::ServerName,
                        extension_data: ExtensionData::ServerName(ServerNameList {
                            server_name_list: vec![ServerName {
                                name_type: NameType::HostName,
                                host_name: hostname.to_string().as_bytes().to_vec(),
                            }],
                        }),
                    },
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::SupportedGroups,
                        extension_data: ExtensionData::SupportedGroups(NamedGroupList {
                            named_group_list: vec![NamedGroup::X25519],
                        }),
                    },
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::SignatureAlgorithms,
                        extension_data: ExtensionData::SignatureAlgorithms(
                            SupportedSignatureAlgorithms {
                                supported_signature_algorithms: vec![SignatureScheme::Ed25519],
                            },
                        ),
                    },
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::KeyShare,
                        extension_data: ExtensionData::KeyShareClientHello(KeyShareClientHello {
                            client_shares: vec![KeyShareEntry {
                                group: NamedGroup::X25519,
                                key_exchange: handshake_keys.dh_client_public.to_bytes().to_vec(),
                            }],
                        }),
                    },
                ],
            };
            info!("Sending ClientHello as follows...\n");
            println!("{client_hello}");
            // Alternative styles
            // dbg!(&client_hello);
            // println!("{client_hello:#?}");
            let handshake = Handshake {
                msg_type: HandshakeType::ClientHello,
                length: u32::try_from(
                    client_hello
                        .as_bytes()
                        .expect("Failed to serialize ClientHello message into bytes")
                        .len(),
                )
                .expect("ClientHello message too long"),
                message: HandshakeMessage::ClientHello(client_hello.clone()),
            };
            let client_handshake_bytes = handshake
                .as_bytes()
                .expect("Failed to serialize Handshake message into bytes");

            transcript_manager.update(&client_handshake_bytes);

            let request_record = TLSRecord {
                record_type: ContentType::Handshake,
                legacy_record_version: TLS_VERSION_COMPATIBILITY,
                length: u16::try_from(client_handshake_bytes.len())
                    .expect("Handshake message too long"),
                fragment: client_handshake_bytes.clone(),
            };
            // Send the constructed request to the server
            match stream.write_all(
                &request_record
                    .as_bytes()
                    .expect("Failed to serialize TLS Record into bytes"),
            ) {
                Ok(()) => {
                    info!("The handshake request has been sent...");
                }
                Err(e) => {
                    error!("Failed to send the request: {e}");
                }
            }
            // Read all the response data into a `VecDeque` buffer
            let buffer = process_tcp_stream(&mut stream).unwrap_or_else(|e| {
                error!("Failed to read the TCP response: {e}");
                std::process::exit(1)
            });
            let response_records = tls13tutorial::get_records(buffer).unwrap_or_else(|e| {
                error!("Failed to process the records: {e}");
                std::process::exit(1)
            });
            for record in response_records {
                handle_tls_record(
                    record,
                    &mut handshake_keys,
                    &mut app_keys,
                    &mut server_certificate,
                    &mut transcript_manager,
                    &mut handshake_complete,
                    hostname,
                    &mut stream,
                );
            }

            // Add the application data exchange here
            if handshake_complete {
                info!("Handshake completed. Starting application data exchange.");

                // Example: Send an HTTP GET request
                let http_request = format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    hostname
                );
                send_application_data(
                    &mut stream,
                    app_keys.as_mut().unwrap(),
                    http_request.as_bytes(),
                )
                .expect("Failed to send application data");

                info!("Sent HTTP request:\n{}", http_request);
                info!("HTTP request length: {}", http_request.as_bytes().len());

                sleep(Duration::from_secs(10));

                // Example: Receive the HTTP response
                let response = receive_application_data(&mut stream, app_keys.as_mut().unwrap())
                    .expect("Failed to receive application data");
                info!("Received response:\n{}", String::from_utf8_lossy(&response));
            } else {
                error!("Handshake not completed. Cannot send application data.");
            }
        }
        Err(e) => {
            error!("Failed to connect: {e}");
        }
    }
}

fn handle_tls_record(
    record: TLSRecord,
    handshake_keys: &mut HandshakeKeys,
    app_keys: &mut Option<ApplicationKeys>,
    server_certificate: &mut Option<tls13tutorial::handshake::Certificate>,
    transcript_manager: &mut TranscriptManager,
    handshake_complete: &mut bool,
    hostname: &str,
    stream: &mut TcpStream,
) {
    match record.record_type {
        ContentType::Alert => match Alert::from_bytes(&mut record.fragment.into()) {
            Ok(alert) => {
                warn!("Alert received: {alert}");
            }
            Err(e) => {
                error!("Failed to parse the alert: {e}");
            }
        },
        ContentType::Handshake => {
            handle_tls_content_type_handshake(record, handshake_keys, transcript_manager);
        }
        ContentType::ApplicationData => {
            // Application data received
            // Decrypt the data using the keys
            // Read TLSInnerPlaintext and proceed with the handshake
            info!("Application data received, size of : {:?}", record.length);
            assert_eq!(record.fragment.len(), record.length as usize);

            // Try to decrypt the record
            match handshake_keys.decrypt_server_handshake(
                &record.fragment,
                record.record_type,
                record.legacy_record_version,
                record.length,
            ) {
                Ok(plaintext) => {
                    // The last byte of the plaintext is the content type
                    if plaintext.is_empty() {
                        error!("Decrypted record is empty");
                        return;
                    }

                    // Debug: Print full plaintext in hex
                    debug!("Raw decrypted data: {}", to_hex(&plaintext));

                    // Extract the content type from the last byte
                    let content_type = plaintext[plaintext.len() - 1];

                    // Slice the plaintext to exclude the last byte (content type)
                    let inner_content = &plaintext[..plaintext.len() - 1];

                    info!(
                        "Decrypted record: content type {} with {} bytes of data",
                        content_type,
                        inner_content.len()
                    );

                    // Handle the decrypted content based on its type
                    match content_type {
                        // ContentType::Handshake value (22)
                        22 => handle_tls_encrypted_handshake(
                            inner_content,
                            transcript_manager,
                            server_certificate,
                            hostname,
                            handshake_keys,
                            stream,
                            handshake_complete,
                            app_keys,
                        ),
                        // ContentType::Alert value (21)
                        21 => {
                            if inner_content.len() == 2 {
                                info!(
                                    "Decrypted alert: level={}, description={}",
                                    inner_content[0], inner_content[1]
                                );
                            } else {
                                error!("Invalid alert format");
                            }
                        }
                        // ContentType::ApplicationData value (23)
                        23 => {
                            info!("Decrypted application data: {} bytes", inner_content.len());
                            // We shouldn't receive application data during handshake
                            warn!("Unexpected application data during handshake");
                        }
                        _ => {
                            warn!("Unknown content type: {}", content_type);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to decrypt record: {}", e);
                }
            }
        }
        ContentType::ChangeCipherSpec => {
            // TLS 1.3 allows but ignores ChangeCipherSpec records
            info!("Received ChangeCipherSpec message (ignored in TLS 1.3)");
            // Nothing to do - this is just for compatibility with middleboxes
        }
        _ => {
            error!("Unexpected response type: {:?}", record.record_type);
            // debug!("Remaining bytes: {:?}", parser.deque);
        }
    }
}

fn handle_tls_content_type_handshake(
    record: TLSRecord,
    handshake_keys: &mut HandshakeKeys,
    transcript_manager: &mut TranscriptManager,
) {
    debug!("Raw handshake data: {:?}", record.fragment);
    // Using clone as the record.fragment is needed later
    let handshake = *Handshake::from_bytes(&mut record.fragment.clone().into())
        .expect("Failed to parse Handshake message");
    debug!("Handshake message: {:?}", &handshake);
    if let HandshakeMessage::ServerHello(server_hello) = handshake.message {
        info!("ServerHello message received");

        // Extract the KeyShare extension from ServerHello
        let mut server_key_share = None;
        for extension in &server_hello.extensions {
            if let ExtensionType::KeyShare = extension.extension_type {
                if let ExtensionData::KeyShareServerHello(key_share) = &extension.extension_data {
                    if let NamedGroup::X25519 = key_share.server_share.group {
                        // Found the X25519 key share from server
                        server_key_share = Some(&key_share.server_share.key_exchange);
                        info!(
                            "Found server's X25519 key share: {}",
                            to_hex(server_key_share.unwrap())
                        );
                        break;
                    }
                }
            }
        }

        // Early return if no compatible key share found
        let server_key_bytes = match server_key_share {
            Some(key_bytes) => {
                info!("Found server's X25519 key share: {}", to_hex(key_bytes));
                key_bytes
            }
            None => {
                error!("Server did not provide an X25519 key share, cannot proceed with handshake");
                std::process::exit(1);
            }
        };

        // Convert server's key exchange bytes to PublicKey and store in handshake_keys
        let server_public_bytes: [u8; 32] = server_key_bytes
            .clone()
            .try_into()
            .expect("Server's public key must be exactly 32 bytes for X25519");
        handshake_keys.dh_server_public = PublicKey::from(server_public_bytes);

        transcript_manager.update(&record.fragment);
        info!(
            "Transcript hash after ServerHello: {}",
            to_hex(transcript_manager.get_current_hash())
        );

        // The key_schedule method will:
        // 1. Calculate the shared secret using Diffie-Hellman
        // 2. Derive handshake secrets using the transcript hash
        // 3. Generate keys and IVs for encryption/decryption
        handshake_keys.key_schedule(transcript_manager.get_current_hash());

        // Reset the sequence numbers when we start a new encrypted communication
        handshake_keys.server_seq_num = 0;
        handshake_keys.client_seq_num = 0;

        info!("Handshake keys derived successfully");
        // Now we have the keys needed to decrypt the following encrypted messages
    }
}

fn handle_tls_encrypted_handshake(
    inner_content: &[u8],
    transcript_manager: &mut TranscriptManager,
    server_certificate: &mut Option<tls13tutorial::handshake::Certificate>,
    hostname: &str,
    handshake_keys: &mut HandshakeKeys,
    stream: &mut TcpStream,
    handshake_complete: &mut bool,
    app_keys: &mut Option<ApplicationKeys>,
) {
    // Parse multiple handshake messages from the decrypted data
    let mut parser = ByteParser::from(inner_content.to_vec());
    while !parser.is_empty() {
        debug!("Parser remaining data: {} bytes", parser.len());
        match Handshake::from_bytes(&mut parser) {
            Ok(handshake) => {
                info!("Decrypted handshake message: {:?}", handshake.msg_type);

                // Serialize the handshake message for the transcript
                let handshake_bytes = handshake
                    .as_bytes()
                    .expect("Failed to serialize handshake message");

                // Save old hash
                let old_hash = transcript_manager.get_current_hash().to_vec();

                // Add transcript hash after handling the message
                transcript_manager.update(&handshake_bytes);

                // Handle different handshake message types
                match handshake.msg_type {
                    HandshakeType::Certificate => {
                        info!("Processing Certificate message");
                        if let HandshakeMessage::Certificate(certificate) = handshake.message {
                            debug!("Certificate: {:?}", certificate);
                            certificate::process_certificate_message(&certificate, hostname)
                                .expect("Failed to process certificate");

                            // Save the certificate for later use
                            *server_certificate = Some(certificate);
                        }
                    }
                    HandshakeType::CertificateVerify => {
                        info!("Processing CertificateVerify message");
                        if let HandshakeMessage::CertificateVerify(cert_verify) = handshake.message
                        {
                            debug!("CertificateVerify received");

                            // Access the saved certificate
                            let certificate = server_certificate
                                .as_ref()
                                .expect("Certificate missing but required for CertificateVerify");

                            // Verify the server's signature using the transcript hash
                            certificate::verify_certificate_signature(
                                &cert_verify,
                                &old_hash,
                                certificate,
                            )
                            .expect("Failed to verify certificate signature");
                        }
                    }
                    HandshakeType::EncryptedExtensions => {
                        info!("Processing EncryptedExtensions message");
                        if let HandshakeMessage::EncryptedExtensions(extensions) = handshake.message
                        {
                            debug!("EncryptedExtensions: {:?}", extensions);
                            process_encrypted_extensions_message(&extensions)
                                .expect("Failed to process EncryptedExtensions");
                        }
                    }
                    HandshakeType::Finished => {
                        info!("Processing Finished message");
                        if let HandshakeMessage::Finished(finished) = handshake.message {
                            debug!("Finished: {:?}", finished);

                            // Pass the finished (which is a Vec<u8>) to the verify function
                            verify_server_finished(
                                &finished.verify_data,
                                &old_hash,
                                &handshake_keys,
                            )
                            .expect("Failed to verify server Finished message");

                            *app_keys = Some(
                                ApplicationKeys::new(
                                    handshake_keys,
                                    transcript_manager.get_current_hash(),
                                )
                                .expect("Failed to derive application traffic keys"),
                            );

                            // Mark handshake as complete
                            info!("Server Finished message received, sending Client Finished");

                            info!("Sending ChangeCipherSpec for compatibility");
                            send_change_cipher_spec(stream)
                                .expect("Failed to send ChangeCipherSpec");

                            // Now create and send Client Finished
                            send_client_finished(
                                stream,
                                handshake_keys,
                                transcript_manager.get_current_hash(),
                            )
                            .expect("Failed to send Client Finished");

                            // Set handshake complete flag
                            *handshake_complete = true;
                            info!("Handshake completed");
                        }
                    }
                    _ => {
                        warn!("Unhandled handshake message type: {:?}", handshake.msg_type);
                    }
                }
            }
            Err(e) => {
                error!("Failed to parse handshake message: {}", e);
                break; // Stop processing if there's an error
            }
        }
    }
}

/// Verify the server's Finished message
fn verify_server_finished(
    finished: &Vec<u8>,
    transcript_hash: &[u8],
    handshake_keys: &HandshakeKeys,
) -> Result<(), String> {
    // Create an HMAC context with the server finished key
    let mut hmac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(&handshake_keys.server_hs_finished_key)
            .map_err(|e| format!("Failed to create HMAC: {}", e))?;

    // Update with the transcript hash
    hmac.update(transcript_hash);

    debug!(
        "Transcript hash used for server finished: {}",
        to_hex(transcript_hash)
    );

    // Compute the expected verify data
    let expected_verify_data = hmac.finalize().into_bytes().to_vec();

    debug!(
        "Expected server verify data: {}",
        tls13tutorial::display::to_hex(&expected_verify_data)
    );
    debug!(
        "Received server verify data: {}",
        tls13tutorial::display::to_hex(finished)
    );

    // warn!("Server Finished message verification not implemented yet");
    // Compare with the received Finished message
    if &expected_verify_data[..] != finished.as_slice() {
        return Err("Server Finished verification failed".to_string());
    }

    info!("Server Finished message verified successfully");
    Ok(())
}

/// Send a ChangeCipherSpec message for middlebox compatibility
///
/// In TLS 1.3, this message is not necessary for the protocol but is included
/// for compatibility with middleboxes that expect it.
fn send_change_cipher_spec(stream: &mut TcpStream) -> Result<(), String> {
    // The ChangeCipherSpec message is a single byte with value 1
    let ccs_data = vec![0x01];

    // Create the TLS record
    let record = TLSRecord {
        record_type: ContentType::ChangeCipherSpec,
        legacy_record_version: TLS_VERSION_COMPATIBILITY,
        length: 1, // ChangeCipherSpec is always 1 byte
        fragment: ccs_data,
    };

    // Serialize and send the record
    let record_bytes = record
        .as_bytes()
        .expect("Failed to serialize ChangeCipherSpec record");

    debug!("Sending ChangeCipherSpec record: {}", to_hex(&record_bytes));

    stream
        .write_all(&record_bytes)
        .map_err(|e| format!("Failed to send ChangeCipherSpec: {}", e))?;

    info!("ChangeCipherSpec sent successfully");
    Ok(())
}

fn send_client_finished(
    stream: &mut TcpStream,
    handshake_keys: &mut HandshakeKeys,
    transcript_hash: &[u8],
) -> Result<(), String> {
    // warn!("Sending Client Finished message not implemented yet");
    // Err(("Sending Client Finished message not implemented yet").to_string())

    // Create verify_data using HMAC with client_hs_finished_key
    let hmac = <Hmac<Sha256> as KeyInit>::new_from_slice(&handshake_keys.client_hs_finished_key)
        .map_err(|e| format!("HMAC error: {}", e))?;
    let mut hmac_ctx = hmac;
    hmac_ctx.update(transcript_hash);
    let verify_data = hmac_ctx.finalize().into_bytes().to_vec();

    debug!("Verify data for Finished: {}", to_hex(&verify_data));

    // Create Finished handshake message
    let finished = HandshakeMessage::Finished(tls13tutorial::handshake::Finished {
        verify_data: verify_data.clone(),
    });
    let handshake = Handshake {
        msg_type: HandshakeType::Finished,
        length: u32::try_from(verify_data.len()).expect("Finished data too long"),
        message: finished,
    };

    let finished_bytes = handshake
        .as_bytes()
        .expect("Failed to serialize Finished message");

    // In TLS 1.3, handshake messages are encrypted after the ServerHello
    // We need to add the content type for the inner plaintext
    let mut plaintext = finished_bytes;
    plaintext.push(ContentType::Handshake as u8);

    // Encrypt the Finished message
    let ciphertext = handshake_keys.encrypt_client_handshake(&plaintext)?;

    // Create the TLS record
    let record = TLSRecord {
        record_type: ContentType::ApplicationData, // All encrypted records use ApplicationData
        legacy_record_version: TLS_VERSION_COMPATIBILITY,
        length: u16::try_from(ciphertext.len()).expect("Ciphertext too long"),
        fragment: ciphertext,
    };

    // Send the record
    let record_bytes = record.as_bytes().expect("Failed to serialize TLS record");

    stream
        .write_all(&record_bytes)
        .map_err(|e| format!("Failed to send Finished message: {}", e))?;

    info!("Client Finished message sent successfully");
    Ok(())
}

/// Process and verify a TLS 1.3 EncryptedExtensions message
/// This function analyzes the extensions provided by the server
fn process_encrypted_extensions_message(
    extensions: &tls13tutorial::handshake::EncryptedExtensions,
) -> Result<(), String> {
    if extensions.extensions.is_empty() {
        info!("Empty EncryptedExtensions received (which is valid in TLS 1.3)");
        return Ok(());
    }

    info!(
        "Received EncryptedExtensions with {} extensions",
        extensions.extensions.len()
    );

    // Log information about each extension in the list
    for ext in &extensions.extensions {
        debug!("Extension type: {:?}", ext.extension_type);

        // Handle specific extensions based on their type
        match ext.extension_type {
            ExtensionType::SupportedGroups => {
                if let ExtensionData::SupportedGroups(groups) = &ext.extension_data {
                    info!("Supported Groups: {:?}", groups.named_group_list);
                }
            }
            ExtensionType::SignatureAlgorithms => {
                if let ExtensionData::SignatureAlgorithms(algorithms) = &ext.extension_data {
                    info!(
                        "Supported Signature Algorithms: {:?}",
                        algorithms.supported_signature_algorithms
                    );
                }
            }
            ExtensionType::ApplicationLayerProtocolNegotiation => {
                if let ExtensionData::Unserialized(data) = &ext.extension_data {
                    info!("ALPN Protocols: {:?}", data);
                }
            }
            ExtensionType::ServerName => {
                info!("ServerName extension received");
                // Check that the sernver name extension is empty
                if let ExtensionData::ServerName(server_name) = &ext.extension_data {
                    if server_name.server_name_list.is_empty() {
                        info!("ServerName extension is empty");
                    } else {
                        warn!("ServerName extension should be empty in EncryptedExtensions");
                    }
                }
            }
            ExtensionType::SupportedVersions => {
                if let ExtensionData::SupportedVersions(versions) = &ext.extension_data {
                    info!("Supported Versions: {:?}", versions.version);
                }
            }
            _ => {
                warn!("Unhandled extension type: {:?}", ext.extension_type);
            }
        }
    }

    info!("EncryptedExtensions processed successfully");
    Ok(())
}

fn receive_application_data(
    stream: &mut TcpStream,
    app_keys: &mut ApplicationKeys,
) -> Result<Vec<u8>, String> {
    loop {
        let buffer = process_tcp_stream(stream).map_err(|e| {
            format!(
                "Failed to read stream during application data reception: {}",
                e
            )
        })?;

        if buffer.is_empty() {
            debug!("process_tcp_stream returned empty buffer while waiting for application data.");
            return Err("No application data received with expected inner content type (stream empty or timed out after processing prior messages)".to_string());
        }

        let response_records = tls13tutorial::get_records(buffer.clone()).map_err(|e| {
            format!(
                "Failed to process records during application data reception: {}",
                e
            )
        })?;

        if response_records.is_empty() && !buffer.is_empty() {
            warn!(
                "Received data ({} bytes) that could not be parsed into any TLS records. Raw data: {}. Continuing to read more.",
                buffer.len(),
                to_hex(&buffer.into_iter().collect::<Vec<u8>>())
            );
            continue;
        }

        for record in response_records {
            match record.record_type {
                ContentType::ApplicationData => {
                    let tls_inner_plaintext = match app_keys.decrypt_server_application_data(
                        &record.fragment,
                        record.record_type,
                        record.legacy_record_version,
                        record.length,
                    ) {
                        Ok(pt) => pt,
                        Err(e) => {
                            error!(
                                "Failed to decrypt ApplicationData record: {}. Skipping record.",
                                e
                            );
                            continue;
                        }
                    };

                    if tls_inner_plaintext.is_empty() {
                        warn!("Decrypted application data (TLSInnerPlaintext) is empty, skipping record.");
                        continue;
                    }

                    let mut end_of_content = tls_inner_plaintext.len();
                    while end_of_content > 0 && tls_inner_plaintext[end_of_content - 1] == 0 {
                        end_of_content -= 1;
                    }

                    if end_of_content == 0 {
                        warn!("Received TLSInnerPlaintext that appears to be all padding or invalid (no content type byte found). Skipping record.");
                        continue;
                    }

                    let inner_content_type_val = tls_inner_plaintext[end_of_content - 1];
                    let actual_payload = tls_inner_plaintext[..end_of_content - 1].to_vec();

                    if inner_content_type_val == ContentType::ApplicationData as u8 {
                        info!(
                            "Received inner ApplicationData (type {}), payload length {}",
                            inner_content_type_val,
                            actual_payload.len()
                        );
                        info!(
                            "Received application data (processed): {}",
                            String::from_utf8_lossy(&actual_payload)
                        );
                        return Ok(actual_payload);
                    } else if inner_content_type_val == ContentType::Handshake as u8 {
                        warn!(
                            "Received inner Handshake message (type {}) within ApplicationData record. Length: {}. Content: {}. Discarding and continuing to look for application data.",
                            inner_content_type_val, actual_payload.len(), to_hex(&actual_payload)
                        );
                        continue;
                    } else if inner_content_type_val == ContentType::Alert as u8 {
                        let alert_level = actual_payload.get(0).copied();
                        let alert_description = actual_payload.get(1).copied();
                        error!( // Changed from warn to error
                            "Received inner Alert message (type {}) within ApplicationData record. Level: {:?}, Description: {:?}. Payload: {}",
                            inner_content_type_val, alert_level, alert_description, to_hex(&actual_payload)
                        );
                        // All alerts in TLS 1.3 are fatal.
                        return Err(format!(
                            "Received fatal alert from server: level {:?}, description {:?}",
                            alert_level, alert_description
                        ));
                    } else {
                        warn!(
                            "Received application data with unexpected inner content type: {}. Length: {}. Content: {}. Discarding and continuing to look for application data.",
                            inner_content_type_val, actual_payload.len(), to_hex(&actual_payload)
                        );
                        continue;
                    }
                }
                ContentType::Alert => {
                    match Alert::from_bytes(&mut record.fragment.clone().into()) {
                        Ok(alert) => {
                            error!("Received top-level Alert record: {}. Terminating.", alert); // Changed from warn
                            return Err(format!(
                                "Received top-level alert: {:?}",
                                alert.description
                            ));
                        }
                        Err(e) => {
                            error!(
                                "Failed to parse top-level Alert record: {}. Skipping record.",
                                e
                            );
                            continue;
                        }
                    }
                }
                _ => {
                    warn!("Received unexpected record type {:?} while waiting for application data. Skipping record.", record.record_type);
                    continue;
                }
            }
        }
        info!("Current batch of records processed. Attempting to read more application data.");
    }
}

fn send_application_data(
    stream: &mut TcpStream,
    app_keys: &mut ApplicationKeys,
    data: &[u8],
) -> Result<(), String> {
    let mut plaintext_for_encryption = data.to_vec();
    // This line is critical for forming TLSInnerPlaintext correctly
    plaintext_for_encryption.push(ContentType::ApplicationData as u8);
    // Encrypt the application data
    let ciphertext = app_keys.encrypt_client_application_data(&plaintext_for_encryption)?;

    // Create the TLS record
    let record = TLSRecord {
        record_type: ContentType::ApplicationData,
        legacy_record_version: TLS_VERSION_COMPATIBILITY,
        length: u16::try_from(ciphertext.len()).expect("Ciphertext too long"),
        fragment: ciphertext,
    };

    // Serialize and send the record
    let record_bytes = record.as_bytes().expect("Failed to serialize TLS record");
    stream
        .write_all(&record_bytes)
        .map_err(|e| format!("Failed to send application data: {}", e))?;

    info!("Application data sent successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_transcript_manager_new() {
        let manager = TranscriptManager::new();
        assert!(manager.messages.is_empty());
        assert!(manager.current_hash.is_empty());
    }

    #[test]
    fn test_transcript_manager_single_update() {
        let mut manager = TranscriptManager::new();
        let message = b"test message";

        manager.update(message);

        // Verify message was stored
        assert_eq!(manager.messages.len(), 1);
        assert_eq!(manager.messages[0], message);

        // Verify hash matches expected value
        let mut hasher = Sha256::new();
        hasher.update(message);
        let expected_hash = hasher.finalize().to_vec();

        assert_eq!(manager.current_hash, expected_hash);
    }

    #[test]
    fn test_transcript_manager_multiple_updates() {
        let mut manager = TranscriptManager::new();
        let message1 = b"first message";
        let message2 = b"second message";
        let message3 = b"third message";

        manager.update(message1);
        manager.update(message2);
        manager.update(message3);

        // Verify all messages were stored in order
        assert_eq!(manager.messages.len(), 3);
        assert_eq!(manager.messages[0], message1);
        assert_eq!(manager.messages[1], message2);
        assert_eq!(manager.messages[2], message3);

        // Verify hash matches expected cumulative value
        let mut hasher = Sha256::new();
        hasher.update(message1);
        hasher.update(message2);
        hasher.update(message3);
        let expected_hash = hasher.finalize().to_vec();

        assert_eq!(manager.current_hash, expected_hash);
    }

    #[test]
    fn test_transcript_manager_get_current_hash() {
        let mut manager = TranscriptManager::new();
        let message = b"test message";

        manager.update(message);

        let mut hasher = Sha256::new();
        hasher.update(message);
        let expected_hash = hasher.finalize().to_vec();

        assert_eq!(manager.get_current_hash(), &expected_hash);
    }

    #[test]
    fn test_transcript_manager_get_messages() {
        let mut manager = TranscriptManager::new();
        let message1 = b"first message";
        let message2 = b"second message";

        manager.update(message1);
        manager.update(message2);

        let messages = manager.get_messages();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0], message1);
        assert_eq!(messages[1], message2);
    }

    #[test]
    fn test_transcript_manager_empty_message() {
        let mut manager = TranscriptManager::new();
        let empty_message = b"";

        manager.update(empty_message);

        // Check that even empty messages are stored
        assert_eq!(manager.messages.len(), 1);
        assert_eq!(manager.messages[0], empty_message);

        // Verify hash matches hash of empty string
        let mut hasher = Sha256::new();
        hasher.update(empty_message);
        let expected_hash = hasher.finalize().to_vec();

        assert_eq!(manager.current_hash, expected_hash);
    }

    #[test]
    fn test_transcript_manager_binary_data() {
        let mut manager = TranscriptManager::new();
        let binary_data = [0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];

        manager.update(&binary_data);

        // Check binary data was stored correctly
        assert_eq!(manager.messages.len(), 1);
        assert_eq!(manager.messages[0], binary_data);

        // Verify hash matches expected value for binary data
        let mut hasher = Sha256::new();
        hasher.update(&binary_data);
        let expected_hash = hasher.finalize().to_vec();

        assert_eq!(manager.current_hash, expected_hash);
    }

    #[test]
    fn test_transcript_hash_matches_incremental_vs_cumulative() {
        // Verify that adding messages incrementally produces the same hash
        // as hashing all messages together
        let mut incremental_manager = TranscriptManager::new();
        let message1 = b"first message";
        let message2 = b"second message";

        incremental_manager.update(message1);
        incremental_manager.update(message2);

        // Create a combined version of the messages for later comparison of internal storage.
        let mut combined = Vec::new();
        combined.extend_from_slice(message1);
        combined.extend_from_slice(message2);

        // Calculate the expected hash by feeding messages sequentially to a standard hasher.
        // This represents the correct cumulative hash.
        let mut hasher = Sha256::new();
        hasher.update(&message1);
        hasher.update(&message2);
        let expected_hash = hasher.finalize().to_vec();

        // Verify that the TranscriptManager's hash after incremental updates matches the expected cumulative hash.
        assert_eq!(incremental_manager.current_hash, expected_hash);
        // Verify that the TranscriptManager stores messages as a list of individual messages,
        // not as a list containing a single concatenated message.
        assert_ne!(incremental_manager.messages, vec![combined]);
    }

    #[test]
    fn test_transcript_manager_reset() {
        let mut manager = TranscriptManager::new();

        // Add some messages
        manager.update(b"first message");
        manager.update(b"second message");

        // "Reset" the manager by creating a new one
        let manager = TranscriptManager::new();

        // Verify it's empty
        assert!(manager.messages.is_empty());
        assert!(manager.current_hash.is_empty());
    }
}
