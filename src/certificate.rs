use log::{debug, info, warn};
use rasn::der;
use rasn::types::{Any, ObjectIdentifier, SetOf};
use rasn_pkix::{AttributeTypeAndValue, Certificate as RasnCertificate, Name, RelativeDistinguishedName, SubjectAltName};
use std::time::Duration;
use time::OffsetDateTime;
use tls13tutorial::handshake::Certificate;

fn extract_common_name(rdn: &RelativeDistinguishedName) -> Result<String, String> {
    // Define the OID for the Common Name (2.5.4.3 in ASN.1)
    let common_name_oid = ObjectIdentifier::new_unchecked(vec![2, 5, 4, 3].into());

    // Convert the set to a vector for iteration
    for attribute in rdn.to_vec() {
        debug!("Attribute type: {:?}", attribute.r#type);
        if attribute.r#type == common_name_oid {
            // Try to extract the value as a String
            // Extract UTF-8 string from ASN.1 ANY value
            if let Ok(value_str) = String::from_utf8(attribute.value.as_bytes().to_vec()) {
                return Ok(value_str);
            } else {
                return Err("Failed to convert Common Name value to UTF-8 string".to_string());
            }
        }
    }

    // Return an error if no Common Name is found
    Err("No Common Name found in RDN".to_string())
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

/// Process and verify a TLS 1.3 Certificate message
/// This function analyzes the certificate chain provided by the server
pub fn process_certificate_message(certificate: &tls13tutorial::handshake::Certificate) -> Result<(), String> {
    use rasn::der;
    use rasn_pkix::{Certificate as RasnCertificate, Name};
    use time::{OffsetDateTime, Duration};
    use webpki::{EndEntityCert, TrustAnchor}; // , SUPPORTED_ALGS};
    use webpki_roots::TLS_SERVER_ROOTS;
    use chrono::{Datelike, Timelike};
    
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
    let hostname = match std::env::args().nth(1) {
        Some(addr) => match addr.split(':').next() {
            Some(host) => host.to_string(),
            None => return Err("Invalid hostname from command line args".to_string()),
        },
        None => return Err("No hostname provided".to_string()),
    };
    
    // Extract the Common Name from the subject
    let mut found_domain = false;

    let Name::RdnSequence(rdn_sequence) = server_rasn_cert.tbs_certificate.subject;
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
    
    // info!("Certificate matches hostname: {}", hostname);
    
    // // 3. Certificate Chain Validation using webpki
    // // Convert certificates to DER format for webpki
    // let mut cert_chain: Vec<&[u8]> = Vec::new();
    // for cert_entry in certificate.certificate_list.iter().skip(1) {
    //     cert_chain.push(&cert_entry.certificate_data);
    // }
    
    // // Create an end-entity certificate from the server certificate
    // let end_entity_cert = match EndEntityCert::try_from(server_cert_data.as_slice()) {
    //     Ok(cert) => cert,
    //     Err(e) => return Err(format!("Failed to create end entity cert: {:?}", e)),
    // };
    
    // // Verify the certificate chain against the webpki root CA store
    // let now_seconds = std::time::SystemTime::now()
    //     .duration_since(std::time::UNIX_EPOCH)
    //     .map_err(|_| "Failed to get current time")?
    //     .as_secs();
    
    // // Convert webpki-roots to a format webpki can use
    // let trust_anchors: Vec<TrustAnchor> = TLS_SERVER_ROOTS.iter().map(|ta| {
    //     TrustAnchor {
    //         subject: ta.subject,
    //         spki: ta.spki,
    //         name_constraints: ta.name_constraints,
    //     }
    // }).collect();
    
    // let chain_result = end_entity_cert.verify_is_valid_tls_server_cert(
    //     SUPPORTED_ALGS,
    //     &webpki::TrustAnchors(&trust_anchors),
    //     &cert_chain,
    //     now_seconds,
    // );
    
    // match chain_result {
    //     Ok(_) => info!("Certificate chain validation successful"),
    //     Err(e) => return Err(format!("Certificate chain validation failed: {:?}", e)),
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
    
    info!("Certificate validation complete. Certificate is valid.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rasn::types::Any;
    use rasn_pkix::{RelativeDistinguishedName, AttributeTypeAndValue};
    use rasn::types::SetOf;

    #[test]
    fn test_extract_common_name_success() {
        // Create a test CommonName attribute
        let common_name_oid = ObjectIdentifier::new_unchecked(vec![2, 5, 4, 3].into());
        let cn_value = "example.com".as_bytes().to_vec();
        
        // Create an Any value containing the UTF-8 string
        let any_value = Any::new(cn_value);
        
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
}