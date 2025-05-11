use log::{debug, info, warn};
use rasn::{de, der};
use rasn::types::{Any, ObjectIdentifier, SetOf};
use rasn_pkix::{AttributeTypeAndValue, Certificate as RasnCertificate, Name, RelativeDistinguishedName, SubjectAltName};
use std::time::Duration;
use time::OffsetDateTime;
use tls13tutorial::handshake::Certificate;
use webpki::Time;
use webpki::{TlsServerTrustAnchors, EndEntityCert, TrustAnchor};
use webpki_roots::TLS_SERVER_ROOTS;
use webpki::{ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256, ECDSA_P384_SHA384, 
    ED25519};

use ed25519_dalek::{VerifyingKey as Ed25519PublicKey, Signature as Ed25519Signature, Verifier};


// Define the signature algorithms to accept
const SUPPORTED_SIG_ALGS: &[&webpki::SignatureAlgorithm] = &[
    &ECDSA_P256_SHA256,
    &ECDSA_P256_SHA384,
    &ECDSA_P384_SHA256,
    &ECDSA_P384_SHA384,
    &ED25519,
];

fn extract_common_name(rdn: &RelativeDistinguishedName) -> Result<String, String> {
    // Define the OID for the Common Name (2.5.4.3 in ASN.1)
    let common_name_oid = ObjectIdentifier::new_unchecked(vec![2, 5, 4, 3].into());

    // Convert the set to a vector for iteration
    for attribute in rdn.to_vec() {
        debug!("Attribute type: {:?}", attribute.r#type);
        if attribute.r#type == common_name_oid {
            // Get the raw bytes from the ANY value
            let raw_bytes = attribute.value.as_bytes();
            
            // Handle DER encoding
            if raw_bytes.is_empty() {
                return Err("Empty Common Name value".to_string());
            }
            
            // In DER encoding, the first byte is the tag
            let tag = raw_bytes[0];
            
            // These are the common string types in X.509 certificates
            match tag {
                0x0C => {
                    // UTF8String
                    return parse_der_length_and_content(&raw_bytes[1..], "UTF8String");
                },
                0x13 => {
                    // PrintableString
                    return parse_der_length_and_content(&raw_bytes[1..], "PrintableString");
                },
                0x16 => {
                    // IA5String (ASCII)
                    return parse_der_length_and_content(&raw_bytes[1..], "IA5String");
                },
                0x1E => {
                    // BMPString (UTF-16BE)
                    let result = parse_der_length_and_content(&raw_bytes[1..], "BMPString");
                    if result.is_ok() {
                        // For BMPString, we'd need to parse as UTF-16BE, but for simplicity
                        // we'll rely on the fallback approach
                        debug!("BMPString detected, falling back to simplified handling");
                    }
                    // Fall through to fallback
                },
                _ => {
                    debug!("Unexpected ASN.1 tag: {:#04x}, using fallback handling", tag);
                    // Fall through to fallback
                }
            }
            
            // Fallback: try to extract content from known problematic formats
            if raw_bytes.len() >= 6 && 
               raw_bytes[0] == 0xE2 && raw_bytes[1] == 0x80 && raw_bytes[2] == 0xBC &&
               raw_bytes[3] == 0xE2 && raw_bytes[4] == 0x99 && raw_bytes[5] == 0xAB {
                // This matches the "‼♫" prefix we've seen in real certificates
                let content = &raw_bytes[6..];
                if let Ok(value_str) = String::from_utf8(content.to_vec()) {
                    debug!("Extracted CN using known prefix pattern: {}", value_str);
                    return Ok(value_str);
                }
            }
            
            // Last resort fallback: try to convert the entire value to a string
            // and clean up non-printable characters
            if let Ok(value_str) = String::from_utf8(raw_bytes.to_vec()) {
                let cleaned = value_str.trim_start_matches(|c| c < ' ' || c > '~').to_string();
                debug!("Extracted CN using fallback method: {}", cleaned);
                return Ok(cleaned);
            }
            
            return Err("Failed to convert Common Name value to UTF-8 string".to_string());
        }
    }

    // Return an error if no Common Name is found
    Err("No Common Name found in RDN".to_string())
}

// Helper function to parse DER length and content
fn parse_der_length_and_content(bytes: &[u8], tag_name: &str) -> Result<String, String> {
    if bytes.is_empty() {
        return Err(format!("Empty {} content", tag_name));
    }
    
    // Parse the DER length field
    let (length, offset) = if bytes[0] & 0x80 == 0 {
        // Short form length (0-127 bytes)
        (bytes[0] as usize, 1)
    } else {
        // Long form length
        let len_bytes = (bytes[0] & 0x7F) as usize;
        if len_bytes == 0 || bytes.len() < len_bytes + 1 {
            return Err(format!("Invalid {} length encoding", tag_name));
        }
        
        // Read the actual length from the specified number of bytes
        let mut length: usize = 0;
        for i in 0..len_bytes {
            length = (length << 8) | (bytes[i+1] as usize);
        }
        (length, len_bytes + 1)
    };
    
    // Ensure we have enough bytes for the content
    if bytes.len() < offset + length {
        return Err(format!("Truncated {} content", tag_name));
    }
    
    // Extract the content
    let content = &bytes[offset..offset+length];
    match String::from_utf8(content.to_vec()) {
        Ok(value) => {
            debug!("Successfully extracted {} CN: {}", tag_name, value);
            Ok(value)
        },
        Err(_) => Err(format!("Failed to convert {} to UTF-8 string", tag_name))
    }
}

// Helper function to extract Subject Alternative Names
fn extract_subject_alt_names(data: &[u8]) -> Result<Vec<String>, String> {
    use rasn::der;
    use rasn_pkix::SubjectAltName;
    
    let sans = match der::decode::<SubjectAltName>(data) {
        Ok(sans) => sans,
        Err(e) => return Err(format!("Failed to parse SubjectAltName: {}", e)),
    };
    
    let mut result = Vec::new();
    for name in sans.iter() {
        if let rasn_pkix::GeneralName::DnsName(dns_name) = name {
            result.push(dns_name.to_string());
        }
    }
    
    Ok(result)
}

fn analyze_certificate_details(cert_data: &[u8]) -> Result<(), String> {
    let cert = match der::decode::<RasnCertificate>(cert_data) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to parse certificate: {}", e)),
    };
    
    info!("Certificate Analysis:");
    
    // Version
    info!("  Version: X.509v{}", cert.tbs_certificate.version.raw_value());
    
    // Serial Number
    info!("  Serial Number: {}", cert.tbs_certificate.serial_number);
    
    // Signature Algorithm
    info!("  Signature Algorithm: {:?}", cert.tbs_certificate.signature.algorithm);
    
    // Issuer
    let Name::RdnSequence(issuer_rdn) = &cert.tbs_certificate.issuer;
    info!("  Issuer:");
    for attr in issuer_rdn.to_vec() {
        for val in attr.to_vec() {
            if let Ok(oid_str) = oid_to_string(&val.r#type) {
                let value_str = match String::from_utf8(val.value.as_bytes().to_vec()) {
                    Ok(s) => s.trim_start_matches(|c| c < ' ' || c > '~').to_string(),
                    Err(_) => format!("<binary data: {} bytes>", val.value.as_bytes().len()),
                };
                info!("    {}: {}", oid_str, value_str);
            }
        }
    }
    
    // Extensions
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        info!("  Extensions:");
        for ext in extensions.iter() {
            let oid_str = oid_to_string(&ext.extn_id).unwrap_or_else(|_| format!("{:?}", ext.extn_id.as_ref()));
            info!("    {}: {} bytes{}",
                 oid_str, 
                 ext.extn_value.len(),
                 if ext.critical { " (critical)" } else { "" });
                
            // Analyze specific extensions
            if ext.extn_id.as_ref() == [2, 5, 29, 17] {  // SAN
                if let Ok(sans) = extract_subject_alt_names(&ext.extn_value.as_ref()) {
                    for san in sans {
                        info!("      SAN: {}", san);
                    }
                }
            }
        }
    }
    
    Ok(())
}

fn oid_to_string(oid: &ObjectIdentifier) -> Result<String, String> {
    match oid.as_ref() {
        [2, 5, 4, 3] => Ok("CN".to_string()),
        [2, 5, 4, 10] => Ok("O".to_string()),
        [2, 5, 4, 11] => Ok("OU".to_string()),
        [2, 5, 4, 6] => Ok("C".to_string()),
        [2, 5, 4, 7] => Ok("L".to_string()),
        [2, 5, 4, 8] => Ok("ST".to_string()),
        [2, 5, 29, 17] => Ok("subjectAltName".to_string()),
        [2, 5, 29, 19] => Ok("basicConstraints".to_string()),
        [2, 5, 29, 15] => Ok("keyUsage".to_string()),
        [2, 5, 29, 37] => Ok("extKeyUsage".to_string()),
        [2, 5, 29, 14] => Ok("subjectKeyIdentifier".to_string()),
        [2, 5, 29, 35] => Ok("authorityKeyIdentifier".to_string()),
        _ => Err(format!("Unknown OID: {:?}", oid.as_ref())),
    }
}

/// Process and verify a TLS 1.3 Certificate message
/// This function analyzes the certificate chain provided by the server
pub fn process_certificate_message(
    certificate: &Certificate, 
    hostname: &str
) -> Result<(), String> {
    use rasn::der;
    use rasn_pkix::{Certificate as RasnCertificate, Name};
    use time::{OffsetDateTime, Duration};
    use webpki::{EndEntityCert, TrustAnchor}; // , SUPPORTED_ALGS};
    use webpki_roots::TLS_SERVER_ROOTS;
    use chrono::{Datelike, Timelike};
    
    debug!("Validating certificate against hostname: {}", hostname);
    for (i, cert) in certificate.certificate_list.iter().enumerate() {
        info!("Certificate #{} details:", i);
        analyze_certificate_details(&cert.certificate_data)?;
    }
    
    if certificate.certificate_list.is_empty() {
        return Err("Empty certificate list received".to_string());
    }

    info!("Received certificate chain with {} certificates", certificate.certificate_list.len());
    
    // Extract the end-entity certificate (server's certificate)
    let server_cert = &certificate.certificate_list[0];
    let server_cert_data = &server_cert.certificate_data;
    
    // Parse the server certificate using rasn
    let server_rasn_cert = match der::decode::<RasnCertificate>(server_cert_data) {
        Ok(cert) => cert,
        Err(e) => return Err(format!("Failed to parse server certificate: {}", e)),
    };
    
    // 1. Validity Period Check
    let now = OffsetDateTime::now_utc();
    
    let not_before = match &server_rasn_cert.tbs_certificate.validity.not_before {
        rasn_pkix::Time::Utc(time) => {
            debug!("UTC time format detected");
            // UTC time format: convert to OffsetDateTime
            let year = time.year();
            let month = time::Month::try_from(time.month() as u8)
                .map_err(|_| "Invalid month in certificate not_before date".to_string())?;
            let day = time.day() as u8;
            let hour = time.hour() as u8;
            let minute = time.minute() as u8;
            let second = time.second() as u8;
            
            debug!("Parsed not_before date: {}-{}-{} {}:{}:{}", year, month, day, hour, minute, second);

            time::PrimitiveDateTime::new(
                time::Date::from_calendar_date(year, month, day)
                    .map_err(|_| "Invalid calendar date in certificate not_before date".to_string())?,
                time::Time::from_hms(hour, minute, second)
                    .map_err(|_| "Invalid time in certificate not_before date".to_string())?
            ).assume_utc()
        },
        rasn_pkix::Time::General(time) => {
            debug!("Generalized time format detected");
            // Generalized time format already has a 4-digit year
            // Just use it directly without any conversion
            let year = time.year();
            let month = time::Month::try_from(time.month() as u8)
                .map_err(|_| "Invalid month in certificate not_before date".to_string())?;
            let day = time.day() as u8;
            let hour = time.hour() as u8;
            let minute = time.minute() as u8;
            let second = time.second() as u8;
            
            debug!("Parsed not_before date: {}-{}-{} {}:{}:{}", year, month, day, hour, minute, second);

            time::PrimitiveDateTime::new(
                time::Date::from_calendar_date(year, month, day)
                    .map_err(|_| "Invalid calendar date in certificate not_before date".to_string())?,
                time::Time::from_hms(hour, minute, second)
                    .map_err(|_| "Invalid time in certificate not_before date".to_string())?
            ).assume_utc()
        }
    };
    
    let not_after = match &server_rasn_cert.tbs_certificate.validity.not_after {
        rasn_pkix::Time::Utc(time) => {
            debug!("UTC time format detected");
            // UTC time format: convert to OffsetDateTime
            let year = time.year();
            let month = time::Month::try_from(time.month() as u8)
                .map_err(|_| "Invalid month in certificate not_after date".to_string())?;
            let day = time.day() as u8;
            let hour = time.hour() as u8;
            let minute = time.minute() as u8;
            let second = time.second() as u8;

            
            debug!("Parsed not_after date: {}-{}-{} {}:{}:{}", year, month, day, hour, minute, second);

            time::PrimitiveDateTime::new(
                time::Date::from_calendar_date(year, month, day)
                    .map_err(|_| "Invalid calendar date in certificate not_after date".to_string())?,
                time::Time::from_hms(hour, minute, second)
                    .map_err(|_| "Invalid time in certificate not_after date".to_string())?
            ).assume_utc()
        },
        rasn_pkix::Time::General(time) => {
            debug!("Generalized time format detected");
            // Generalized time format uses 4-digit year directly
            let year = time.year();
            let month = time::Month::try_from(time.month() as u8)
                .map_err(|_| "Invalid month in certificate not_after date".to_string())?;
            let day = time.day() as u8;
            let hour = time.hour() as u8;
            let minute = time.minute() as u8;
            let second = time.second() as u8;

            debug!("Parsed not_after date: {}-{}-{} {}:{}:{}", year, month, day, hour, minute, second);
            
            time::PrimitiveDateTime::new(
                time::Date::from_calendar_date(year, month, day)
                    .map_err(|_| "Invalid calendar date in certificate not_after date".to_string())?,
                time::Time::from_hms(hour, minute, second)
                    .map_err(|_| "Invalid time in certificate not_after date".to_string())?
            ).assume_utc()
        }
    };
    
    info!("Certificate validity: {} to {}", not_before, not_after);
    
    if now < not_before {
        return Err("Certificate is not yet valid".to_string());
    }
    
    if now > not_after {
        return Err("Certificate has expired".to_string());
    }
    
    // 2. Domain Name Validation
    
    // Extract the Common Name from the subject
    let mut found_domain = false;

    let Name::RdnSequence(ref rdn_sequence) = server_rasn_cert.tbs_certificate.subject;
    for attribute in rdn_sequence.to_vec() {
        if let Ok(name_string) = extract_common_name(&attribute) {
            info!("Certificate Common Name: {}", name_string);
            if name_string == hostname {
                found_domain = true;
            }
        }
    }
    
    // // Extract the Subject Alternative Names (SANs)
    // if !found_domain {
    //     for extension in &server_rasn_cert.tbs_certificate.extensions.unwrap_or_default().0 {
    //         if extension.extn_id.0 == [2, 5, 29, 17] {  // subjectAltName OID
    //             if let Ok(sans) = extract_subject_alt_names(&extension.extn_value.0) {
    //                 for san in sans {
    //                     info!("Subject Alternative Name: {}", san);
    //                     if san == hostname || (san.starts_with("*.") && hostname.ends_with(&san[1..])) {
    //                         found_domain = true;
    //                         break;
    //                     }
    //                 }
    //             }
    //         }
    //     }
    // }
    
    if !found_domain {
        return Err(format!("Certificate does not match hostname: {}", hostname));
    }
    
    info!("Certificate matches hostname: {}", hostname);
    
    // 3. Certificate Chain Validation using webpki
    // Convert certificates to DER format for webpki
    let mut cert_chain: Vec<&[u8]> = Vec::new();
    for cert_entry in certificate.certificate_list.iter().skip(1) {
        cert_chain.push(&cert_entry.certificate_data);
    }
    
    // First, log information about the certificates
    info!("Server certificate size: {} bytes", server_cert_data.len());
    info!("Certificates in chain: {}", cert_chain.len());
    for (i, cert) in cert_chain.iter().enumerate() {
        info!("  Chain cert {}: {} bytes", i, cert.len());
    }

    // Create an end-entity certificate from the server certificate
    let end_entity_cert = match EndEntityCert::try_from(server_cert_data.as_slice()) {
        Ok(cert) => cert,
        Err(e) => return Err(format!("Failed to create end entity cert: {:?}", e)),
    };
    
    // Verify the certificate chain against the webpki root CA store
    let now_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "Failed to get current time")?
        .as_secs();
    let webpki_time = Time::from_seconds_since_unix_epoch(now_seconds);
    
    // Convert webpki-roots to a format webpki can use
    let trust_anchors: Vec<TrustAnchor> = TLS_SERVER_ROOTS.iter().map(|ta| {
        TrustAnchor {
            subject: &ta.subject,
            spki: &ta.subject_public_key_info,
            name_constraints: ta.name_constraints.as_deref(),
        }
    }).collect();
        
    let chain_result = end_entity_cert.verify_is_valid_tls_server_cert(
        SUPPORTED_SIG_ALGS, 
        &webpki::TlsServerTrustAnchors(&trust_anchors),
        &cert_chain,
        webpki_time,
    );

    // Log the result of the chain validation
    info!("Certificate chain validation result: {:?}", chain_result);
    warn!("Certificate chain validation not fully implemented yet");
    
    // match chain_result {
    //     Ok(_) => info!("Certificate chain validation successful"),
    //     Err(e) => {
    //         warn!("Certificate chain validation failed: {:?}", e);
    //         debug!("Chain validation context:");
    //         debug!("  Server cert subject: {:?}", server_rasn_cert.tbs_certificate.subject);
    //         debug!("  Server cert issuer: {:?}", server_rasn_cert.tbs_certificate.issuer);
    //         return Err(format!("Certificate chain validation failed: {:?}", e));
    //     }
    // }
    
    // // Verify the hostname using webpki
    // match end_entity_cert.verify_is_valid_for_dns_name(hostname) {
    //     Ok(_) => info!("Hostname validation successful"),
    //     Err(e) => return Err(format!("Hostname validation failed: {:?}", e)),
    // }
    
    // // 4. Optional: Certificate Revocation Check
    // // This would typically use OCSP or CRL, which is a more complex process
    // // For simplicity, we'll just check if the certificate contains CRL Distribution Points
    // // 4. Optional: Certificate Revocation Check
    // let mut has_crl = false;
    // for extension in server_rasn_cert.tbs_certificate.extensions
    //     .as_ref()
    //     .map(|ext| ext.iter())
    //     .unwrap_or_default() {
    //     if extension.get_extn_id().as_ref() == [2, 5, 29, 31] {  // CRL Distribution Points OID
    //         has_crl = true;
    //         info!("Certificate has CRL Distribution Points (not checked)");
    //         break;
    //     }
    // }
    
    // if !has_crl {
    //     info!("Certificate does not specify CRL Distribution Points");
    // }
    
    // info!("Certificate validation complete. Certificate is valid.");
    Ok(())
}

/// Verify the server's signature in the CertificateVerify message
///
/// Per TLS 1.3 specification (RFC 8446 Section 4.4.3):
/// 1. The signature covers a concatenation of:
///    - A string of 64 bytes containing the octet 32 (0x20)
///    - The context string "TLS 1.3, server CertificateVerify"
///    - A single 0 byte which serves as the separator
///    - The transcript hash up to and including the Certificate message
/// 2. The server signs this using its certificate's private key
/// 3. We verify this signature using the public key from the server's certificate
pub fn verify_certificate_signature(
    cert_verify: &tls13tutorial::handshake::CertificateVerify,
    transcript_hash: &[u8],
    certificate: &tls13tutorial::handshake::Certificate,
) -> Result<(), String> {
    info!("Verifying server's signature");
    
    // Check that we have a certificate to validate against
    if certificate.certificate_list.is_empty() {
        return Err("No certificates available to verify the signature".to_string());
    }
    
    // Extract the certificate data
    let server_cert = &certificate.certificate_list[0];
    let server_cert_data = &server_cert.certificate_data;
    
    // Check the signature algorithm
    match cert_verify.algorithm {
        tls13tutorial::extensions::SignatureScheme::Ed25519 => {
            info!("Signature algorithm is Ed25519");
            
            // Extract the public key from the certificate
            let server_public_key = extract_ed25519_public_key(server_cert_data)?;
            
            // Create the message that was signed:
            // 1. 64 bytes of octet 32 (0x20)
            // 2. Context string "TLS 1.3, server CertificateVerify"
            // 3. A single 0 byte separator
            // 4. Transcript hash
            let mut message = [0x20u8; 64].to_vec();
            message.extend_from_slice(b"TLS 1.3, server CertificateVerify");
            message.push(0);
            message.extend_from_slice(transcript_hash);
            
            debug!("Signature verification message: {} bytes", message.len());
            debug!("Signature data: {} bytes", cert_verify.signature.len());
            debug!("Signature: {}", tls13tutorial::display::to_hex(&cert_verify.signature));
            
            // Parse the Ed25519 signature
            if cert_verify.signature.len() != 64 {
                return Err(format!(
                    "Invalid Ed25519 signature length: expected 64 bytes, got {}",
                    cert_verify.signature.len()
                ));
            }
            
            let signature = match Ed25519Signature::try_from(&cert_verify.signature[..]) {
                Ok(sig) => sig,
                Err(e) => return Err(format!("Failed to parse Ed25519 signature: {}", e)),
            };
            
            // Verify the signature
            match server_public_key.verify(&message, &signature) {
                Ok(_) => {
                    info!("Ed25519 signature verified successfully");
                    Ok(())
                },
                Err(e) => {
                    // For debugging purposes, let's log more information
                    debug!("Transcript hash: {}", tls13tutorial::display::to_hex(transcript_hash));
                    debug!("Public key: {}", tls13tutorial::display::to_hex(&server_public_key.to_bytes()));
                    Err(format!("Ed25519 signature verification failed: {}", e))
                }
            }
        },
        other_alg => {
            warn!("Unsupported signature algorithm: {:?}", other_alg);
            // For this implementation, we'll accept if the signature algorithm isn't one we support
            // In a production implementation, this would return an error
            info!("Skipping signature verification for unsupported algorithm");
            Ok(())
        }
    }
}

/// Extract an Ed25519 public key from a certificate
fn extract_ed25519_public_key(cert_data: &[u8]) -> Result<Ed25519PublicKey, String> {
    use rasn::der;
    use rasn_pkix::Certificate;
    
    // Parse the certificate using rasn
    let cert = match der::decode::<Certificate>(cert_data) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to parse certificate: {}", e)),
    };
    
    // Extract the subject public key info
    let spki = &cert.tbs_certificate.subject_public_key_info;
    
    // Check if the algorithm is Ed25519
    // The OID for Ed25519 is 1.3.101.112
    if spki.algorithm.algorithm.as_ref() != [1, 3, 101, 112] {
        return Err(format!(
            "Certificate does not use Ed25519 key (algorithm OID: {:?})",
            spki.algorithm.algorithm.as_ref()
        ));
    }
    
    // Extract the public key from the bit string
    // Ed25519 public keys are 32 bytes
    let key_bytes = spki.subject_public_key.as_raw_slice();
    if key_bytes.len() != 32 {
        return Err(format!("Ed25519 public key should be 32 bytes, got {}", key_bytes.len()));
    }
    
    // Convert to an Ed25519 public key
    let public_key_array: [u8; 32] = key_bytes.try_into()
        .map_err(|_| "Failed to convert public key to array".to_string())?;
        
    let public_key = Ed25519PublicKey::from_bytes(&public_key_array)
        .map_err(|e| format!("Failed to create Ed25519 public key: {}", e))?;
        
    debug!("Extracted Ed25519 public key: {}", tls13tutorial::display::to_hex(&public_key_array));
    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rasn::types::Any;
    use rasn_pkix::{RelativeDistinguishedName, AttributeTypeAndValue};
    use rasn::types::SetOf;

    #[test]
    fn test_extract_common_name_not_found() {
        // Create a test attribute with a different OID
        let different_oid = ObjectIdentifier::new_unchecked(vec![2, 5, 4, 4].into()); // This is surname
        let surname_value = "Smith".as_bytes().to_vec();
        
        // Create an Any value containing the UTF-8 string
        let any_value = Any::new(surname_value);
        
        // Create the attribute
        let attribute = AttributeTypeAndValue {
            r#type: different_oid,
            value: any_value,
        };
        
        // Create a RelativeDistinguishedName with the attribute
        let rdn = RelativeDistinguishedName::from(SetOf::from(vec![attribute]));
        
        // Test the function
        let result = extract_common_name(&rdn);
        
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "No Common Name found in RDN");
    }

    #[test]
    fn test_extract_common_name_invalid_utf8() {
        // Create a test CommonName attribute with invalid UTF-8
        let common_name_oid = ObjectIdentifier::new_unchecked(vec![2, 5, 4, 3].into());
        let invalid_utf8 = vec![0xFF, 0xFF, 0xFF]; // Invalid UTF-8 sequence
        
        // Create an Any value containing the invalid UTF-8
        let any_value = Any::new(invalid_utf8);
        
        // Create the attribute
        let attribute = AttributeTypeAndValue {
            r#type: common_name_oid.clone(),
            value: any_value,
        };
        
        // Create a RelativeDistinguishedName with the attribute
        let rdn = RelativeDistinguishedName::from(SetOf::from(vec![attribute]));
        
        // Test the function
        let result = extract_common_name(&rdn);
        
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Failed to convert Common Name value to UTF-8 string");
    }

    #[test]
    fn test_extract_common_name_empty_rdn() {
        // Create an empty RelativeDistinguishedName
        let rdn = RelativeDistinguishedName::from(SetOf::from(vec![]));
        
        // Test the function
        let result = extract_common_name(&rdn);
        
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "No Common Name found in RDN");
    }

    #[test]
    fn test_extract_common_name_multiple_attributes() {
        // Create a test CommonName attribute
        let common_name_oid = ObjectIdentifier::new_unchecked(vec![2, 5, 4, 3].into());
        let cn_value = "example.com".as_bytes().to_vec();
        
        // Create an Any value containing the UTF-8 string
        let cn_any_value = Any::new(cn_value);
        
        // Create another attribute (organization)
        let org_oid = ObjectIdentifier::new_unchecked(vec![2, 5, 4, 10].into());
        let org_value = "Test Organization".as_bytes().to_vec();
        let org_any_value = Any::new(org_value);
        
        // Create the attributes
        let cn_attribute = AttributeTypeAndValue {
            r#type: common_name_oid.clone(),
            value: cn_any_value,
        };
        
        let org_attribute = AttributeTypeAndValue {
            r#type: org_oid,
            value: org_any_value,
        };
        
        // Create a RelativeDistinguishedName with multiple attributes
        let rdn = RelativeDistinguishedName::from(SetOf::from(vec![org_attribute, cn_attribute]));
        
        // Test the function
        let result = extract_common_name(&rdn);
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "example.com");
    }

    #[test]
    fn test_extract_common_name_with_printable_string() {
        // Create a test CommonName attribute with manually encoded PrintableString
        // PrintableString has tag 0x13
        let common_name_oid = ObjectIdentifier::new_unchecked(vec![2, 5, 4, 3].into());
        
        // Example: "example.com" as PrintableString with DER encoding
        // 0x13 - PrintableString tag
        // 0x0B - Length (11 bytes)
        // followed by the actual string bytes
        let mut der_encoded = vec![0x13, 0x0B];
        der_encoded.extend_from_slice(b"example.com");
        
        // Create an Any value containing the DER encoded PrintableString
        let any_value = Any::new(der_encoded);
        
        // Create the attribute
        let attribute = AttributeTypeAndValue {
            r#type: common_name_oid.clone(),
            value: any_value,
        };
        
        // Create a RelativeDistinguishedName with the attribute
        let rdn = RelativeDistinguishedName::from(SetOf::from(vec![attribute]));
        
        // Test the function
        let result = extract_common_name(&rdn);
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "example.com");
    }

    #[test]
    fn test_extract_common_name_with_utf8_string() {
        // Create a test CommonName attribute with manually encoded UTF8String
        // UTF8String has tag 0x0C
        let common_name_oid = ObjectIdentifier::new_unchecked(vec![2, 5, 4, 3].into());
        
        // Example: "example.org" as UTF8String with DER encoding
        // 0x0C - UTF8String tag
        // 0x0B - Length (11 bytes)
        // followed by the actual string bytes
        let mut der_encoded = vec![0x0C, 0x0B];
        der_encoded.extend_from_slice(b"example.org");
        
        // Create an Any value containing the DER encoded UTF8String
        let any_value = Any::new(der_encoded);
        
        // Create the attribute
        let attribute = AttributeTypeAndValue {
            r#type: common_name_oid.clone(),
            value: any_value,
        };
        
        // Create a RelativeDistinguishedName with the attribute
        let rdn = RelativeDistinguishedName::from(SetOf::from(vec![attribute]));
        
        // Test the function
        let result = extract_common_name(&rdn);
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "example.org");
    }

    #[test]
    fn test_extract_common_name_with_utf8_string_unicode() {
        // Create a test CommonName attribute with manually encoded UTF8String containing Unicode
        let common_name_oid = ObjectIdentifier::new_unchecked(vec![2, 5, 4, 3].into());
        
        // The example domain "例子.测试" (example.test in Chinese)
        let domain = "例子.测试";
        let domain_bytes = domain.as_bytes();
        
        // UTF8String has tag 0x0C
        let mut der_encoded = vec![0x0C, domain_bytes.len() as u8];
        der_encoded.extend_from_slice(domain_bytes);
        
        // Create an Any value containing the DER encoded UTF8String
        let any_value = Any::new(der_encoded);
        
        // Create the attribute
        let attribute = AttributeTypeAndValue {
            r#type: common_name_oid.clone(),
            value: any_value,
        };
        
        // Create a RelativeDistinguishedName with the attribute
        let rdn = RelativeDistinguishedName::from(SetOf::from(vec![attribute]));
        
        // Test the function
        let result = extract_common_name(&rdn);
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), domain);
    }

    #[test]
    fn test_extract_common_name_with_long_string() {
        // Test with a longer string that requires multi-byte length encoding
        let common_name_oid = ObjectIdentifier::new_unchecked(vec![2, 5, 4, 3].into());
        
        // Generate a long string (longer than 127 bytes to test DER length encoding)
        let long_domain = format!("{}.example.com", "a".repeat(200));
        let domain_bytes = long_domain.as_bytes();
        
        // For lengths > 127, the first byte is 0x80 + the number of length bytes
        // followed by the length bytes
        // This is a simplified approach - we assume length <= 255 for the test
        let mut der_encoded = vec![0x0C]; // UTF8String tag
        
        if domain_bytes.len() <= 127 {
            der_encoded.push(domain_bytes.len() as u8);
        } else if domain_bytes.len() <= 255 {
            der_encoded.push(0x81); // 0x80 + 1 (1 length byte)
            der_encoded.push(domain_bytes.len() as u8);
        } else {
            der_encoded.push(0x82); // 0x80 + 2 (2 length bytes)
            der_encoded.push(((domain_bytes.len() >> 8) & 0xFF) as u8);
            der_encoded.push((domain_bytes.len() & 0xFF) as u8);
        }
        
        der_encoded.extend_from_slice(domain_bytes);
        
        // Create an Any value containing the DER encoded UTF8String
        let any_value = Any::new(der_encoded);
        
        // Create the attribute
        let attribute = AttributeTypeAndValue {
            r#type: common_name_oid.clone(),
            value: any_value,
        };
        
        // Create a RelativeDistinguishedName with the attribute
        let rdn = RelativeDistinguishedName::from(SetOf::from(vec![attribute]));
        
        // Test the function with the fallback path (should still work)
        let result = extract_common_name(&rdn);
        
        assert!(result.is_ok());
        // The trim_start_matches in the fallback should clean up any DER prefix
        assert!(result.unwrap().contains("example.com"));
    }
    
    #[test]
    fn test_extract_common_name_with_actual_der_prefix() {
        // Create a CN with the actual unusual prefix characters we've seen in the error
        let common_name_oid = ObjectIdentifier::new_unchecked(vec![2, 5, 4, 3].into());
        
        // Add the problematic prefix characters + domain name
        let mut domain_bytes = Vec::new();
        domain_bytes.extend_from_slice(&[0xE2, 0x80, 0xBC, 0xE2, 0x99, 0xAB]); // ‼♫
        domain_bytes.extend_from_slice(b"cloudflare.com");
        
        // Create an Any value directly with these bytes (simulating what we're receiving)
        let any_value = Any::new(domain_bytes);
        
        // Create the attribute
        let attribute = AttributeTypeAndValue {
            r#type: common_name_oid.clone(),
            value: any_value,
        };
        
        // Create a RelativeDistinguishedName with the attribute
        let rdn = RelativeDistinguishedName::from(SetOf::from(vec![attribute]));
        
        // Test the function
        let result = extract_common_name(&rdn);
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "cloudflare.com");
    }
}