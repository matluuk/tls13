//! # TLS Extensions and their encoding/decoding
//!
//! Includes `ByteSerializable` trait for converting structures into bytes and constructing again.
use crate::handshake::ProtocolVersion;
use crate::parser::ByteParser;
use ::log::{debug, warn};

/// `ByteSerializable` trait is used to serialize and deserialize the struct into bytes
pub trait ByteSerializable {
    /// Returns the byte representation of the object if possible
    fn as_bytes(&self) -> Option<Vec<u8>>;
    /// Attempts to parse the bytes into a struct object implementing this trait
    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>>;
}

/// Helper to identify the origin of the extension (client or server)
/// Extension data format is different for client and server on some cases
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ExtensionOrigin {
    Client,
    Server,
}

/// `Extension` is wrapper for any TLS extension
#[derive(Debug, Clone)]
pub struct Extension {
    pub origin: ExtensionOrigin,
    pub extension_type: ExtensionType, // Defined maximum value can be 65535, takes 2 bytes to present
    pub extension_data: ExtensionData, // length of the data can be 0..2^16-1 (2 bytes to present)
}

impl Extension {
    pub(crate) fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice((self.extension_type as u16).to_be_bytes().as_ref());
        let ext_bytes = self.extension_data.as_bytes()?;
        // 2 byte length determinant for the `extension_data`
        bytes.extend(u16::try_from(ext_bytes.len()).ok()?.to_be_bytes());
        bytes.extend_from_slice(&ext_bytes);
        Some(bytes)
    }

    pub(crate) fn from_bytes(
        bytes: &mut ByteParser,
        origin: ExtensionOrigin,
    ) -> std::io::Result<Box<Self>> {
        let ext_type = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid extension type")
        })?;
        debug!("ExtensionType: {:?}", ext_type);

        let ext_data_len = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid extension data length",
            )
        })?;
        debug!("Extension data length: {}", ext_data_len);
        let ext_data = bytes.get_bytes(ext_data_len as usize);
        let mut ext_bytes = ByteParser::from(ext_data);
        debug!("Extension data: {:?}", ext_bytes);
        let extension_data = match ext_type {
            // TODO Implement the rest of the extension types
            0 => {
                if origin == ExtensionOrigin::Server {
                    // For server-side SNI, the extension data must be empty
                    if ext_data_len != 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Server SNI extension must have empty data",
                        ));
                    }
                    debug!("Parsed empty Server Name Indication (SNI) extension");
                    ExtensionData::ServerName(ServerNameList {
                        server_name_list: Vec::new(),
                    })
                } else {
                    // Parse client-side SNI normally
                    ExtensionData::ServerName(*ServerNameList::from_bytes(&mut ext_bytes)?)
                }
            },
            10 => {
                // SupportedGroups extension
                debug!("Parsing SupportedGroups extension");
                ExtensionData::SupportedGroups(*NamedGroupList::from_bytes(&mut ext_bytes)?)
            }
            13 => {
                // SignatureAlgorithms extension
                debug!("Parsing SignatureAlgorithms extension");
                ExtensionData::SignatureAlgorithms(*SupportedSignatureAlgorithms::from_bytes(
                    &mut ext_bytes,
                )?)
            }
            51 => {
                // KeyShare extension - handle differently based on origin
                if origin == ExtensionOrigin::Server {
                    debug!("Parsing KeyShareServerHello extension");
                    ExtensionData::KeyShareServerHello(*KeyShareServerHello::from_bytes(
                        &mut ext_bytes,
                    )?)
                } else {
                    debug!("Parsing KeyShareClientHello extension");
                    ExtensionData::KeyShareClientHello(*KeyShareClientHello::from_bytes(
                        &mut ext_bytes,
                    )?)
                }
            }
            43 => {
                // SupportedVersions extension
                debug!("Parsing SupportedVersions extension");
                if origin == ExtensionOrigin::Server {
                    // For server, parse as selected version
                    let version = ext_bytes.get_u16().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid version")
                    })?;
                    ExtensionData::SupportedVersions(SupportedVersions {
                        version: VersionKind::Selected(version),
                    })
                } else {
                    ExtensionData::Unserialized(ext_bytes.drain())
                }
            }
            45 => {
                // PskKeyExchangeModes extension
                debug!("Parsing PskKeyExchangeModes extension");
                ExtensionData::PskKeyExchangeModes(*PskKeyExchangeModes::from_bytes(
                    &mut ext_bytes,
                )?)
            }
            _ => {
                warn!("Unknown ExtensionType: {}", ext_type);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid extension data",
                ));
            }
        };
        Ok(Box::new(Extension {
            origin,
            extension_type: ext_type.into(),
            extension_data,
        }))
    }
}

/// `ExtensionType` where maximum value can be 2^16-1 (2 bytes to present)
#[derive(Debug, Copy, Clone)]
pub enum ExtensionType {
    ServerName = 0,
    MaxFragmentLength = 1,
    StatusRequest = 5,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heartbeat = 15,
    ApplicationLayerProtocolNegotiation = 16,
    SignedCertificateTimestamp = 18,
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    Padding = 21,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OidFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
}
/// By using `From` trait, we can convert `u16` to `ExtensionType`, e.g. by using `.into()`
impl From<u16> for ExtensionType {
    fn from(value: u16) -> Self {
        match value {
            0 => ExtensionType::ServerName,
            1 => ExtensionType::MaxFragmentLength,
            5 => ExtensionType::StatusRequest,
            10 => ExtensionType::SupportedGroups,
            13 => ExtensionType::SignatureAlgorithms,
            14 => ExtensionType::UseSrtp,
            15 => ExtensionType::Heartbeat,
            16 => ExtensionType::ApplicationLayerProtocolNegotiation,
            18 => ExtensionType::SignedCertificateTimestamp,
            19 => ExtensionType::ClientCertificateType,
            20 => ExtensionType::ServerCertificateType,
            21 => ExtensionType::Padding,
            41 => ExtensionType::PreSharedKey,
            42 => ExtensionType::EarlyData,
            43 => ExtensionType::SupportedVersions,
            44 => ExtensionType::Cookie,
            45 => ExtensionType::PskKeyExchangeModes,
            47 => ExtensionType::CertificateAuthorities,
            48 => ExtensionType::OidFilters,
            49 => ExtensionType::PostHandshakeAuth,
            50 => ExtensionType::SignatureAlgorithmsCert,
            51 => ExtensionType::KeyShare,
            _ => {
                warn!("Unknown ExtensionType: {}", value);
                ExtensionType::ServerName
            }
        }
    }
}
/// `ExtensionData` is a wrapper for any data in the extension
/// TODO not all extension data types are implemented or added
#[derive(Debug, Clone)]
pub enum ExtensionData {
    ServerName(ServerNameList),
    SupportedGroups(NamedGroupList),
    SignatureAlgorithms(SupportedSignatureAlgorithms),
    SupportedVersions(SupportedVersions),
    KeyShareClientHello(KeyShareClientHello),
    KeyShareServerHello(KeyShareServerHello),
    PskKeyExchangeModes(PskKeyExchangeModes),
    Unserialized(Vec<u8>), // Placeholder for unimplemented extension data
}

impl ByteSerializable for ExtensionData {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        match self {
            ExtensionData::ServerName(server_name_list) => server_name_list.as_bytes(),
            ExtensionData::SupportedGroups(named_group_list) => named_group_list.as_bytes(),
            ExtensionData::SignatureAlgorithms(supported_signature_algorithms) => {
                supported_signature_algorithms.as_bytes()
            }
            ExtensionData::SupportedVersions(supported_versions) => supported_versions.as_bytes(),
            ExtensionData::KeyShareClientHello(key_share_client_hello) => {
                key_share_client_hello.as_bytes()
            }
            ExtensionData::KeyShareServerHello(key_share_server_hello) => {
                key_share_server_hello.as_bytes()
            }
            ExtensionData::PskKeyExchangeModes(psk_key_exchange_modes) => {
                psk_key_exchange_modes.as_bytes()
            }
            ExtensionData::Unserialized(data) => Some(data.clone()),
        }
    }

    fn from_bytes(_bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        todo!()
    }
}

/// Kinds of `ProtocolVersion` - client offers multiple versions where a server selects one.
#[derive(Debug, Clone)]
pub enum VersionKind {
    Suggested(Vec<ProtocolVersion>), // length of the data can be 2..254 on client, 1 byte to present
    Selected(ProtocolVersion),
}

/// # Supported versions extension
#[derive(Debug, Clone)]
pub struct SupportedVersions {
    pub version: VersionKind,
}

impl ByteSerializable for SupportedVersions {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        match &self.version {
            VersionKind::Suggested(versions) => {
                for version in versions {
                    bytes.extend_from_slice(&version.to_be_bytes());
                }
                // 1 byte length determinant for `versions`
                bytes.splice(
                    0..0,
                    u8::try_from(bytes.len())
                        .ok()?
                        .to_be_bytes()
                        .iter()
                        .copied(),
                );
            }
            VersionKind::Selected(version) => {
                bytes.extend_from_slice(&version.to_be_bytes());
            }
        }
        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // It takes at least 3 bytes to present ClientHello
        // Not the best for validation, but it's a start
        if bytes.len() > 2 {
            todo!("We don't support receiving ClientHello")
        } else {
            // Server format: just a single selected version (2 bytes)
            let selected_version = bytes.get_u16().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid selected version")
            })?;

            debug!("Server selected version: {:04x}", selected_version);

            Ok(Box::new(SupportedVersions {
                version: VersionKind::Selected(selected_version),
            }))
        }
    }
}

/// Server Name extension, as defined in [RFC 6066](https://datatracker.ietf.org/doc/html/rfc6066#section-3)
/// `HostName` contains the fully qualified DNS hostname of the server,
/// as understood by the client.  The hostname is represented as a byte
/// string using ASCII encoding without a trailing dot.  This allows the
/// support of internationalized domain names through the use of A-labels
/// defined in RFC5890.  DNS hostnames are case-insensitive.  The
/// algorithm to compare hostnames is described in RFC5890, Section
/// 2.3.2.4.
#[derive(Debug, Clone)]
pub struct ServerName {
    pub name_type: NameType,
    pub host_name: HostName,
}
impl std::fmt::Display for ServerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = String::from_utf8_lossy(&self.host_name);
        writeln!(f, "{:?}: {}", self.name_type, name)
    }
}

/// `NameType` where maximum value be `u8::MAX` (1 byte)
#[derive(Debug, Copy, Clone)]
pub enum NameType {
    HostName = 0,
}
/// `HostName` is a byte string using ASCII encoding of host without a trailing dot
type HostName = Vec<u8>;
/// `ServerNameList` is a list of `ServerName` structures, where maximum length be `u16::MAX` (2 bytes)
#[derive(Debug, Clone)]
pub struct ServerNameList {
    pub server_name_list: Vec<ServerName>,
}
impl std::fmt::Display for ServerNameList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for server_name in &self.server_name_list {
            writeln!(f, "{server_name}")?;
        }
        Ok(())
    }
}

impl ByteSerializable for ServerNameList {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        for server_name in &self.server_name_list {
            bytes.push(server_name.name_type as u8);
            // 2 byte length determinant for the ASCII byte presentation of the name
            bytes.extend_from_slice(
                u16::try_from(server_name.host_name.len())
                    .ok()?
                    .to_be_bytes()
                    .as_ref(),
            );
            bytes.extend_from_slice(&server_name.host_name);
        }
        // 2 byte length determinant for the whole `ServerNameList`
        bytes.splice(
            0..0,
            u16::try_from(bytes.len())
                .ok()?
                .to_be_bytes()
                .iter()
                .copied(),
        );
        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // First get the total length of the list
        let list_len = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid server name list length",
            )
        })?;

        let mut server_name_list = Vec::new();
        let mut remaining = list_len as usize;

        while remaining > 0 && !bytes.is_empty() {
            // Get the name type (1 byte)
            let name_type = bytes.get_u8().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid name type")
            })?;

            // Currently only HostName (0) is defined
            if name_type != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unsupported name type: {}", name_type),
                ));
            }

            // Get the host name length (2 bytes)
            let host_name_len = bytes.get_u16().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid host name length")
            })?;

            // Get the host name bytes
            let host_name = bytes.get_bytes(host_name_len as usize);
            if host_name.len() != host_name_len as usize {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Insufficient host name data",
                ));
            }

            // Add the server name to the list
            server_name_list.push(ServerName {
                name_type: NameType::HostName,
                host_name,
            });

            // Update remaining bytes counter
            // 1 byte for name_type + 2 bytes for host_name_len + host_name_len bytes
            remaining = remaining.saturating_sub(3 + host_name_len as usize);
        }

        // Ensure we consumed exactly the amount specified by list_len
        if remaining > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Malformed server name list data",
            ));
        }

        debug!(
            "Parsed ServerNameList with {} entries",
            server_name_list.len()
        );

        Ok(Box::new(ServerNameList { server_name_list }))
    }
}

/// ## Signature Algorithm Extension
/// Our client primarily supports signature scheme Ed25519
/// Value takes 2 bytes to represent.
/// See more [here.](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.3)
#[derive(Debug, Copy, Clone)]
pub enum SignatureScheme {
    /* RSASSA-PKCS1-v1_5 algorithms */
    RsaPkcs1Sha256 = 0x0401,
    RsaPkcs1Sha384 = 0x0501,
    RsaPkcs1Sha512 = 0x0601,
    /* ECDSA algorithms */
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    EcdsaSecp521r1Sha512 = 0x0603,
    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805,
    RsaPssRsaeSha512 = 0x0806,
    /* EdDSA algorithms */
    Ed25519 = 0x0807, // NOTE The only supported signature scheme
    Ed448 = 0x0808,
    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    RsaPssPssSha256 = 0x0809,
    RsaPssPssSha384 = 0x080a,
    RsaPssPssSha512 = 0x080b,
    /* Legacy algorithms */
    RsaPkcs1Sha1 = 0x0201,
    EcdsaSha1 = 0x0203,
    /* Reserved Code Points */
    // PrivateUse(0xFE00..0xFFFF),
}
impl ByteSerializable for SignatureScheme {
    //noinspection DuplicatedCode
    fn as_bytes(&self) -> Option<Vec<u8>> {
        match *self as u32 {
            #[allow(clippy::cast_possible_truncation)]
            value if u16::try_from(value).is_ok() => Some((value as u16).to_be_bytes().to_vec()),
            _ => None,
        }
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        match bytes.get_u16().ok_or_else(ByteParser::insufficient_data)? {
            0x0401 => Ok(Box::new(SignatureScheme::RsaPkcs1Sha256)),
            0x0501 => Ok(Box::new(SignatureScheme::RsaPkcs1Sha384)),
            0x0601 => Ok(Box::new(SignatureScheme::RsaPkcs1Sha512)),
            0x0403 => Ok(Box::new(SignatureScheme::EcdsaSecp256r1Sha256)),
            0x0503 => Ok(Box::new(SignatureScheme::EcdsaSecp384r1Sha384)),
            0x0603 => Ok(Box::new(SignatureScheme::EcdsaSecp521r1Sha512)),
            0x0804 => Ok(Box::new(SignatureScheme::RsaPssRsaeSha256)),
            0x0805 => Ok(Box::new(SignatureScheme::RsaPssRsaeSha384)),
            0x0806 => Ok(Box::new(SignatureScheme::RsaPssRsaeSha512)),
            0x0807 => Ok(Box::new(SignatureScheme::Ed25519)),
            0x0808 => Ok(Box::new(SignatureScheme::Ed448)),
            0x0809 => Ok(Box::new(SignatureScheme::RsaPssPssSha256)),
            0x080a => Ok(Box::new(SignatureScheme::RsaPssPssSha384)),
            0x080b => Ok(Box::new(SignatureScheme::RsaPssPssSha512)),
            0x0201 => Ok(Box::new(SignatureScheme::RsaPkcs1Sha1)),
            0x0203 => Ok(Box::new(SignatureScheme::EcdsaSha1)),
            value => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid SignatureScheme value: 0x{:04x}", value),
            )),
        }
    }
}
#[derive(Debug, Clone)]
pub struct SupportedSignatureAlgorithms {
    pub supported_signature_algorithms: Vec<SignatureScheme>, // length of the data can be 2..2^16-2
}
impl ByteSerializable for SupportedSignatureAlgorithms {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        for signature_scheme in &self.supported_signature_algorithms {
            bytes.extend_from_slice(&signature_scheme.as_bytes()?);
        }
        // 2 byte length determinant for the whole `SupportedSignatureAlgorithms`
        bytes.splice(0..0, u16::try_from(bytes.len()).ok()?.to_be_bytes());
        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // First get the total length of the supported signature algorithms list
        let list_len = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid supported signature algorithms list length",
            )
        })?;

        // Make sure the list length is valid (at least one algorithm, and even number of bytes)
        if list_len == 0 || list_len % 2 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid supported signature algorithms list length: {}",
                    list_len
                ),
            ));
        }

        let mut supported_signature_algorithms = Vec::new();
        let mut remaining = list_len as usize;

        // Each signature scheme is 2 bytes
        while remaining >= 2 && !bytes.is_empty() {
            let signature_scheme = *SignatureScheme::from_bytes(bytes)?;
            supported_signature_algorithms.push(signature_scheme);
            remaining -= 2;
        }

        // Make sure we consumed exactly the amount of bytes specified by list_len
        if remaining > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Malformed supported signature algorithms list data",
            ));
        }

        debug!(
            "Parsed SupportedSignatureAlgorithms with {} algorithms",
            supported_signature_algorithms.len()
        );

        Ok(Box::new(SupportedSignatureAlgorithms {
            supported_signature_algorithms,
        }))
    }
}

/// ## Supported Groups Extension
/// Our client supports primarily Elliptic Curve Diffie-Hellman (ECDH) with Curve25519
/// Parameters for ECDH goes to opaque `key_exchange` field of a `KeyShareEntry` in a `KeyShare` structure.
/// Max size is (0xFFFF), takes 2 bytes to present
/// See more in [here.](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.4)
#[derive(Debug, Copy, Clone)]
pub enum NamedGroup {
    /* Elliptic Curve Groups (ECDHE) */
    Secp256r1 = 0x0017,
    Secp384r1 = 0x0018,
    Secp521r1 = 0x0019,
    X25519 = 0x001D, // NOTE The only supported named group
    X448 = 0x001E,
    /* Finite Field Groups (DHE) */
    Ffdhe2048 = 0x0100,
    Ffdhe3072 = 0x0101,
    Ffdhe4096 = 0x0102,
    Ffdhe6144 = 0x0103,
    Ffdhe8192 = 0x0104,
    /* Reserved Code Points */
    // ffdhe_private_use(0x01FC..0x01FF),
    // ecdhe_private_use(0xFE00..0xFEFF),
}
impl ByteSerializable for NamedGroup {
    //noinspection DuplicatedCode
    fn as_bytes(&self) -> Option<Vec<u8>> {
        match *self as u32 {
            #[allow(clippy::cast_possible_truncation)]
            value if u16::try_from(value).is_ok() => Some((value as u16).to_be_bytes().to_vec()),
            _ => None,
        }
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        match bytes.get_u16().ok_or_else(ByteParser::insufficient_data)? {
            0x0017 => Ok(Box::new(NamedGroup::Secp256r1)),
            0x0018 => Ok(Box::new(NamedGroup::Secp384r1)),
            0x0019 => Ok(Box::new(NamedGroup::Secp521r1)),
            0x001D => Ok(Box::new(NamedGroup::X25519)),
            0x001E => Ok(Box::new(NamedGroup::X448)),
            0x0100 => Ok(Box::new(NamedGroup::Ffdhe2048)),
            0x0101 => Ok(Box::new(NamedGroup::Ffdhe3072)),
            0x0102 => Ok(Box::new(NamedGroup::Ffdhe4096)),
            0x0103 => Ok(Box::new(NamedGroup::Ffdhe6144)),
            0x0104 => Ok(Box::new(NamedGroup::Ffdhe8192)),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid NamedGroup",
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NamedGroupList {
    pub named_group_list: Vec<NamedGroup>, // (2 bytes to present)
}
impl ByteSerializable for NamedGroupList {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        for named_group in &self.named_group_list {
            bytes.extend_from_slice(&named_group.as_bytes()?);
        }
        // 2 byte length determinant for `named_group_list`
        bytes.splice(
            0..0,
            u16::try_from(bytes.len())
                .ok()?
                .to_be_bytes()
                .iter()
                .copied(),
        );
        Some(bytes)
    }

    fn from_bytes(_bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // First get the length of the list
        let list_len = _bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid named group list length",
            )
        })?;

        let mut named_group_list = Vec::new();
        let mut remaining = list_len as usize;

        // Each named group is 2 bytes
        while remaining >= 2 && !_bytes.is_empty() {
            let group = *NamedGroup::from_bytes(_bytes)?;
            named_group_list.push(group);
            remaining -= 2;
        }

        // Make sure we consumed exactly the amount of bytes specified by list_len
        if remaining > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Malformed named group list data",
            ));
        }

        Ok(Box::new(NamedGroupList { named_group_list }))
    }
}

/// ## `KeyShare` Extension
#[derive(Debug, Clone)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub key_exchange: Vec<u8>, // (2 bytes to present the length)
}
impl ByteSerializable for KeyShareEntry {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend(self.group.as_bytes()?);
        // 2 byte length determinant for the `key_exchange`
        bytes.extend(
            u16::try_from(self.key_exchange.len())
                .ok()?
                .to_be_bytes()
                .as_ref(),
        );
        bytes.extend_from_slice(&self.key_exchange);
        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // First parse the named group
        let group = *NamedGroup::from_bytes(bytes)?;

        // Then get the length of the key exchange data
        let key_exchange_len = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid key exchange length",
            )
        })?;

        // Extract the key exchange data
        let key_exchange = bytes.get_bytes(key_exchange_len as usize);
        if key_exchange.len() != key_exchange_len as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Insufficient key exchange data",
            ));
        }

        Ok(Box::new(KeyShareEntry {
            group,
            key_exchange,
        }))
    }
}

/// There are three different structures for `KeyShare` extension
/// One for `ClientHello`, one for `HelloRetryRequest` and one for `ServerHello`
/// The order in the vector `KeyShareEntry` should be same as in `SupportedGroups` extension
#[derive(Debug, Clone)]
pub struct KeyShareClientHello {
    pub client_shares: Vec<KeyShareEntry>, // (2 bytes to present the length)
}

impl ByteSerializable for KeyShareClientHello {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        for client_share in &self.client_shares {
            bytes.extend_from_slice(&client_share.as_bytes()?);
        }
        // 2 byte length determinant for `client_shares`
        bytes.splice(
            0..0,
            u16::try_from(bytes.len())
                .ok()?
                .to_be_bytes()
                .iter()
                .copied(),
        );
        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // First get the total length of the client shares
        let list_len = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid key share client hello length",
            )
        })?;

        let mut client_shares = Vec::new();
        let mut remaining = list_len as usize;

        // Parse each key share entry until we've consumed the entire list
        while remaining > 0 && !bytes.is_empty() {
            // Create a marker to track how many bytes we consume
            let start_pos = bytes.len();

            // Parse a key share entry
            let entry = *KeyShareEntry::from_bytes(bytes)?;

            // Calculate how many bytes were consumed
            let bytes_consumed = start_pos - bytes.len();
            if bytes_consumed > remaining {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Malformed key share entry data",
                ));
            }

            client_shares.push(entry);
            remaining -= bytes_consumed;
        }

        // Make sure we consumed exactly the amount of bytes specified by list_len
        if remaining > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Malformed key share client hello data",
            ));
        }

        debug!(
            "Parsed KeyShareClientHello with {} entries",
            client_shares.len()
        );

        Ok(Box::new(KeyShareClientHello { client_shares }))
    }
}
/// `key_share` extension data structure in `ServerHello`
/// Contains only single `KeyShareEntry` when compared to `KeyShareClientHello`
#[derive(Debug, Clone)]
pub struct KeyShareServerHello {
    pub server_share: KeyShareEntry,
}
impl ByteSerializable for KeyShareServerHello {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        self.server_share.as_bytes()
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        Ok(Box::new(KeyShareServerHello {
            server_share: *KeyShareEntry::from_bytes(bytes)?,
        }))
    }
}

/// Modes for pre-shared key (PSK) key exchange
/// Client-only
/// 1 byte to present
#[derive(Debug, Copy, Clone)]
pub enum PskKeyExchangeMode {
    PskKe = 0,
    PskDheKe = 1,
}
/// ## `psk_key_exchange_modes` extension
/// A client MUST provide a `PskKeyExchangeModes` extension if it
///  offers a `pre_shared_key` extension.
#[derive(Debug, Clone)]
pub struct PskKeyExchangeModes {
    pub ke_modes: Vec<PskKeyExchangeMode>, // (1 byte to present the length)
}

impl ByteSerializable for PskKeyExchangeModes {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        for ke_mode in &self.ke_modes {
            bytes.push(*ke_mode as u8);
        }
        // 1 byte length determinant for `ke_modes`
        bytes.splice(
            0..0,
            u8::try_from(bytes.len())
                .ok()?
                .to_be_bytes()
                .iter()
                .copied(),
        );
        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // First get the length of the modes list
        let list_len = bytes.get_u8().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid PSK key exchange modes list length",
            )
        })?;

        let mut ke_modes = Vec::new();
        let mut remaining = list_len as usize;

        // Each mode is 1 byte
        while remaining > 0 && !bytes.is_empty() {
            let mode = bytes.get_u8().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Insufficient data for PSK key exchange mode",
                )
            })?;

            // Validate the mode value
            match mode {
                0 => ke_modes.push(PskKeyExchangeMode::PskKe),
                1 => ke_modes.push(PskKeyExchangeMode::PskDheKe),
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Invalid PSK key exchange mode: {}", mode),
                    ))
                }
            }

            remaining -= 1;
        }

        // Make sure we consumed exactly the amount of bytes specified by list_len
        if remaining > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Malformed PSK key exchange modes list data",
            ));
        }

        debug!("Parsed PskKeyExchangeModes with {} modes", ke_modes.len());

        Ok(Box::new(PskKeyExchangeModes { ke_modes }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_server_name_list() {
        let server_name_list = ServerNameList {
            server_name_list: vec![ServerName {
                name_type: NameType::HostName,
                host_name: "example.ulfheim.net".as_bytes().to_vec(),
            }],
        };
        let bytes = server_name_list.as_bytes().unwrap();
        assert_eq!(bytes.len(), 24);
        assert_eq!(
            bytes,
            vec![
                0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75,
                0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74
            ]
        );

        // Test the from_bytes implementation
        let mut parser = ByteParser::from(bytes.clone());
        let parsed = *ServerNameList::from_bytes(&mut parser).unwrap();

        assert_eq!(parsed.server_name_list.len(), 1);
        assert_eq!(
            parsed.server_name_list[0].name_type as u8,
            NameType::HostName as u8
        );
        assert_eq!(
            parsed.server_name_list[0].host_name,
            "example.ulfheim.net".as_bytes().to_vec()
        );
    }

    #[test]
    fn test_extension_server_name_list() {
        let extension = Extension {
            origin: ExtensionOrigin::Client,
            extension_type: ExtensionType::ServerName,
            extension_data: ExtensionData::ServerName(ServerNameList {
                server_name_list: vec![ServerName {
                    name_type: NameType::HostName,
                    host_name: "example.ulfheim.net".as_bytes().to_vec(),
                }],
            }),
        };
        let bytes = extension.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![
                0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70,
                0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74
            ]
        );
    }

    #[test]
    fn test_supported_versions() {
        // Test the client format (suggested versions)
        let client_versions = SupportedVersions {
            version: VersionKind::Suggested(vec![0x0304, 0x0303]),
        };
        let bytes = client_versions.as_bytes().unwrap();
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes, vec![0x04, 0x03, 0x04, 0x03, 0x03]); // Length + TLS 1.3 + TLS 1.2

        // Test the server format (selected version)
        let server_version = SupportedVersions {
            version: VersionKind::Selected(0x0304),
        };
        let bytes = server_version.as_bytes().unwrap();
        assert_eq!(bytes.len(), 2);
        assert_eq!(bytes, vec![0x03, 0x04]); // TLS 1.3

        // Test parsing server format
        let mut parser = ByteParser::from(vec![0x03, 0x04]);
        let parsed = *SupportedVersions::from_bytes(&mut parser).unwrap();
        match parsed.version {
            VersionKind::Selected(version) => assert_eq!(version, 0x0304),
            _ => panic!("Expected VersionKind::Selected"),
        }
    }

    #[test]
    fn test_named_group() {
        // Test serialization
        assert_eq!(NamedGroup::X25519.as_bytes().unwrap(), vec![0x00, 0x1D]);
        assert_eq!(NamedGroup::Secp256r1.as_bytes().unwrap(), vec![0x00, 0x17]);

        // Test deserialization
        let mut parser = ByteParser::from(vec![0x00, 0x1D]);
        let parsed = *NamedGroup::from_bytes(&mut parser).unwrap();
        assert!(matches!(parsed, NamedGroup::X25519));

        let mut parser = ByteParser::from(vec![0x00, 0x17]);
        let parsed = *NamedGroup::from_bytes(&mut parser).unwrap();
        assert!(matches!(parsed, NamedGroup::Secp256r1));
    }

    #[test]
    fn test_named_group_list() {
        let named_group_list = NamedGroupList {
            named_group_list: vec![NamedGroup::X25519, NamedGroup::Secp256r1],
        };
        let bytes = named_group_list.as_bytes().unwrap();
        assert_eq!(bytes.len(), 6); // 2 bytes for length + 2 bytes per group
        assert_eq!(bytes, vec![0x00, 0x04, 0x00, 0x1D, 0x00, 0x17]);

        // Test deserialization
        let mut parser = ByteParser::from(bytes);
        let parsed = *NamedGroupList::from_bytes(&mut parser).unwrap();

        assert_eq!(parsed.named_group_list.len(), 2);
        assert!(matches!(parsed.named_group_list[0], NamedGroup::X25519));
        assert!(matches!(parsed.named_group_list[1], NamedGroup::Secp256r1));
    }

    #[test]
    fn test_key_share_entry() {
        // Create test data
        let key_share_entry = KeyShareEntry {
            group: NamedGroup::X25519,
            key_exchange: vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        };

        // Test serialization
        let bytes = key_share_entry.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![
                0x00, 0x1D, // X25519
                0x00, 0x20, // length 32
                // key exchange data - 32 bytes
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                0x1D, 0x1E, 0x1F, 0x20
            ]
        );

        // Test deserialization
        let mut parser = ByteParser::from(bytes);
        let parsed = *KeyShareEntry::from_bytes(&mut parser).unwrap();

        assert!(matches!(parsed.group, NamedGroup::X25519));
        assert_eq!(parsed.key_exchange.len(), 32);
        assert_eq!(parsed.key_exchange, key_share_entry.key_exchange);
    }

    #[test]
    fn test_key_share_server_hello() {
        // Create a test key share
        let key_share = KeyShareServerHello {
            server_share: KeyShareEntry {
                group: NamedGroup::X25519,
                key_exchange: vec![
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                    23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
                ],
            },
        };

        // Serialize
        let bytes = key_share.as_bytes().unwrap();

        // Test serialization
        assert_eq!(
            bytes,
            vec![
                0x00, 0x1D, // X25519
                0x00, 0x20, // length 32
                // key exchange data - 32 bytes
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                0x1D, 0x1E, 0x1F, 0x20
            ]
        );

        // Test deserialization
        let mut parser = ByteParser::from(bytes);
        let parsed = *KeyShareServerHello::from_bytes(&mut parser).unwrap();

        assert!(matches!(parsed.server_share.group, NamedGroup::X25519));
        assert_eq!(parsed.server_share.key_exchange.len(), 32);
        assert_eq!(
            parsed.server_share.key_exchange,
            key_share.server_share.key_exchange
        );
    }

    #[test]
    fn test_key_share_client_hello() {
        // Create a test key share
        let key_share = KeyShareClientHello {
            client_shares: vec![
                KeyShareEntry {
                    group: NamedGroup::X25519,
                    key_exchange: vec![
                        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                        22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
                    ],
                },
                KeyShareEntry {
                    group: NamedGroup::Secp256r1,
                    key_exchange: vec![5, 5, 5, 5, 5, 5, 5, 5],
                },
            ],
        };

        // Serialize
        let bytes = key_share.as_bytes().unwrap();

        // Test serialization - should have length prefix followed by entries
        assert_eq!(bytes.len(), 2 + 36 + 12); // 2 bytes length + 36 bytes X25519 entry + 12 bytes Secp256r1 entry
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 48); // Total length 48 bytes
        assert_eq!(bytes[2], 0x00);
        assert_eq!(bytes[3], 0x1D); // X25519

        // Test deserialization - create mock data that would be returned by from_bytes
        let test_bytes = vec![
            0x00, 0x30, // length 48 bytes
            // First entry - X25519
            0x00, 0x1D, // X25519
            0x00, 0x20, // length 32
            // 32 bytes of key data
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20, // Second entry - Secp256r1
            0x00, 0x17, // Secp256r1
            0x00, 0x08, // length 8
            0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, // key data
        ];

        // This mocks what the function would do when implemented
        let mut parser = ByteParser::from(test_bytes);
        let parsed = *KeyShareClientHello::from_bytes(&mut parser).unwrap();

        assert_eq!(parsed.client_shares.len(), 2);
        assert!(matches!(parsed.client_shares[0].group, NamedGroup::X25519));
        assert_eq!(parsed.client_shares[0].key_exchange.len(), 32);
        assert!(matches!(
            parsed.client_shares[1].group,
            NamedGroup::Secp256r1
        ));
        assert_eq!(parsed.client_shares[1].key_exchange.len(), 8);
    }

    #[test]
    fn test_signature_scheme() {
        // Test serialization
        assert_eq!(
            SignatureScheme::Ed25519.as_bytes().unwrap(),
            vec![0x08, 0x07]
        );
        assert_eq!(
            SignatureScheme::RsaPkcs1Sha256.as_bytes().unwrap(),
            vec![0x04, 0x01]
        );

        // Test deserialization with mock data
        let test_bytes = vec![0x08, 0x07]; // Ed25519
        let mut parser = ByteParser::from(test_bytes);
        let parsed = *SignatureScheme::from_bytes(&mut parser).unwrap();
        assert!(matches!(parsed, SignatureScheme::Ed25519));

        let test_bytes = vec![0x04, 0x01]; // RsaPkcs1Sha256
        let mut parser = ByteParser::from(test_bytes);
        let parsed = *SignatureScheme::from_bytes(&mut parser).unwrap();
        assert!(matches!(parsed, SignatureScheme::RsaPkcs1Sha256));

        // Test invalid value handling
        let test_bytes = vec![0xFF, 0xFF]; // Invalid value
        let mut parser = ByteParser::from(test_bytes);
        let result = SignatureScheme::from_bytes(&mut parser);
        assert!(result.is_err());
    }

    #[test]
    fn test_supported_signature_algorithms() {
        // Create test data
        let supported_sig_algs = SupportedSignatureAlgorithms {
            supported_signature_algorithms: vec![
                SignatureScheme::Ed25519,
                SignatureScheme::EcdsaSecp256r1Sha256,
            ],
        };

        // Test serialization
        let bytes = supported_sig_algs.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![
                0x00, 0x04, // length 4 bytes
                0x08, 0x07, // Ed25519
                0x04, 0x03 // EcdsaSecp256r1Sha256
            ]
        );

        // Test deserialization with mock data
        let test_bytes = vec![
            0x00, 0x04, // length 4 bytes
            0x08, 0x07, // Ed25519
            0x04, 0x03, // EcdsaSecp256r1Sha256
        ];

        let mut parser = ByteParser::from(test_bytes);
        let parsed = *SupportedSignatureAlgorithms::from_bytes(&mut parser).unwrap();

        assert_eq!(parsed.supported_signature_algorithms.len(), 2);
        assert!(matches!(
            parsed.supported_signature_algorithms[0],
            SignatureScheme::Ed25519
        ));
        assert!(matches!(
            parsed.supported_signature_algorithms[1],
            SignatureScheme::EcdsaSecp256r1Sha256
        ));

        // Test invalid length
        let test_bytes = vec![
            0x00, 0x04, // length 4 bytes
            0x08, 0x07, // Only one algorithm when two are expected
        ];

        let mut parser = ByteParser::from(test_bytes);
        let result = SupportedSignatureAlgorithms::from_bytes(&mut parser);
        assert!(result.is_err());
    }

    #[test]
    fn test_psk_key_exchange_modes() {
        // Create test data
        let psk_modes = PskKeyExchangeModes {
            ke_modes: vec![PskKeyExchangeMode::PskDheKe, PskKeyExchangeMode::PskKe],
        };

        // Test serialization
        let bytes = psk_modes.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![
                0x02, // length 2 bytes
                0x01, // PskDheKe
                0x00  // PskKe
            ]
        );

        // Test deserialization
        let test_bytes = vec![
            0x02, // length 2 bytes
            0x01, // PskDheKe
            0x00, // PskKe
        ];

        let mut parser = ByteParser::from(test_bytes);
        let parsed = *PskKeyExchangeModes::from_bytes(&mut parser).unwrap();

        assert_eq!(parsed.ke_modes.len(), 2);
        assert!(matches!(parsed.ke_modes[0], PskKeyExchangeMode::PskDheKe));
        assert!(matches!(parsed.ke_modes[1], PskKeyExchangeMode::PskKe));

        // Test invalid mode value
        let test_bytes = vec![
            0x01, // length 1 byte
            0x02, // Invalid mode
        ];

        let mut parser = ByteParser::from(test_bytes);
        let result = PskKeyExchangeModes::from_bytes(&mut parser);
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "Client hello format parsing not yet implemented"]
    fn test_supported_versions_client_hello() {
        // Test the client format (suggested versions)
        let client_versions = SupportedVersions {
            version: VersionKind::Suggested(vec![0x0304, 0x0303]),
        };
        let bytes = client_versions.as_bytes().unwrap();
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes, vec![0x04, 0x03, 0x04, 0x03, 0x03]); // Length + TLS 1.3 + TLS 1.2

        // Test parsing client format
        let test_bytes = vec![0x04, 0x03, 0x04, 0x03, 0x03]; // Length + TLS 1.3 + TLS 1.2
        let mut parser = ByteParser::from(test_bytes);

        let parsed = *SupportedVersions::from_bytes(&mut parser).unwrap();

        match parsed.version {
            VersionKind::Suggested(versions) => {
                assert_eq!(versions.len(), 2);
                assert_eq!(versions[0], 0x0304); // TLS 1.3
                assert_eq!(versions[1], 0x0303); // TLS 1.2
            }
            _ => panic!("Expected VersionKind::Suggested"),
        }
    }
}
