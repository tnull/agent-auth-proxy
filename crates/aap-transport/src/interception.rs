//! Downstream TLS identities constructed only after host-side admission.

use aap_types::{ErrorCode, Result, proxy::ConnectAuthority};
use rcgen::{
    CertificateParams, ExtendedKeyUsagePurpose, Issuer, KeyPair, KeyUsagePurpose, PublicKeyData,
};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    sign::CertifiedKey,
};
use std::sync::Arc;

fn validated_root(certificate: &[u8]) -> Result<x509_parser::certificate::X509Certificate<'_>> {
    let invalid = || aap_types::Error::new(ErrorCode::InspectionUnavailable);
    if certificate.len() > 64 * 1024 {
        return Err(invalid());
    }
    let (remaining, root) =
        x509_parser::parse_x509_certificate(certificate).map_err(|_| invalid())?;
    if !remaining.is_empty()
        || root.subject() != root.issuer()
        || !root.validity().is_valid()
        || !root
            .basic_constraints()
            .map_err(|_| invalid())?
            .is_some_and(|extension| extension.value.ca)
        || !root
            .key_usage()
            .map_err(|_| invalid())?
            .is_some_and(|extension| extension.value.key_cert_sign())
    {
        return Err(invalid());
    }
    root.extensions_map().map_err(|_| invalid())?;
    // Only the declared self-signed root profile is supported. Do not ignore
    // name constraints, EKU, or unknown extensions when constructing an issuer.
    if root.extensions().iter().any(|extension| {
        !matches!(
            extension.oid.to_id_string().as_str(),
            "2.5.29.19" | "2.5.29.15" | "2.5.29.14" | "2.5.29.35"
        )
    }) {
        return Err(invalid());
    }
    root.verify_signature(None).map_err(|_| invalid())?;
    Ok(root)
}

/// Validate the supported public CA profile without reading its private key.
pub fn certificate_expiry(certificate: &CertificateDer<'_>) -> Result<std::time::SystemTime> {
    let root = validated_root(certificate)?;
    let seconds = u64::try_from(root.validity().not_after.timestamp())
        .map_err(|_| ErrorCode::InspectionUnavailable)?;
    std::time::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(seconds))
        .ok_or_else(|| ErrorCode::InspectionUnavailable.into())
}

/// Consume a private PKCS#8 CA key and issue one short-lived endpoint identity.
/// The caller must authorize the CONNECT target and revalidate its store lease.
/// No key, certificate cache, or trust-root installation is owned by this module.
pub fn configuration(
    certificate: CertificateDer<'static>,
    private_key: Vec<u8>,
    authority: &ConnectAuthority,
) -> Result<Arc<ServerConfig>> {
    let invalid = || aap_types::Error::new(ErrorCode::InspectionUnavailable);
    if private_key.len() > 64 * 1024 {
        return Err(invalid());
    }
    let root = validated_root(&certificate)?;
    let now = time::OffsetDateTime::now_utc();
    let not_before = root
        .validity()
        .not_before
        .to_datetime()
        .max(now - time::Duration::minutes(5));
    let not_after = root
        .validity()
        .not_after
        .to_datetime()
        .min(now + time::Duration::minutes(10));
    if not_after <= now + time::Duration::seconds(1) {
        return Err(invalid());
    }
    let key = KeyPair::try_from(&PrivatePkcs8KeyDer::from(private_key)).map_err(|_| invalid())?;
    if root.public_key().raw != key.subject_public_key_info() {
        return Err(invalid());
    }
    let issuer = Issuer::from_ca_cert_der(&certificate, key).map_err(|_| invalid())?;
    let leaf_key = KeyPair::generate().map_err(|_| invalid())?;
    let mut params =
        CertificateParams::new(vec![authority.host().to_owned()]).map_err(|_| invalid())?;
    params.not_before = not_before;
    params.not_after = not_after;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = params
        .signed_by(&leaf_key, &issuer)
        .map_err(|_| invalid())?;
    let provider = rustls::crypto::ring::default_provider();
    let key = CertifiedKey::from_der(
        vec![leaf.der().clone(), certificate],
        PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
        &provider,
    )
    .map_err(|_| invalid())?;
    key.keys_match().map_err(|_| invalid())?;
    let resolver = AdmittedCertificate {
        host: authority.host().to_owned(),
        key: Arc::new(key),
    };
    let mut configuration = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid())?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    configuration.alpn_protocols = vec![b"http/1.1".to_vec()];
    configuration.max_early_data_size = 0;
    configuration.send_tls13_tickets = 0;
    configuration.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(Arc::new(configuration))
}

struct AdmittedCertificate {
    host: String,
    key: Arc<CertifiedKey>,
}
impl std::fmt::Debug for AdmittedCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdmittedCertificate")
    }
}
impl rustls::server::ResolvesServerCert for AdmittedCertificate {
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let matches = match hello.server_name() {
            Some(name) => name.eq_ignore_ascii_case(&self.host),
            None => self.host.parse::<std::net::IpAddr>().is_ok(),
        };
        matches.then(|| self.key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn root() -> (CertificateDer<'static>, Vec<u8>) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(7);
        (
            params.self_signed(&key).unwrap().der().clone(),
            key.serialize_der(),
        )
    }
    async fn handshake(
        configuration: Arc<ServerConfig>,
        root: CertificateDer<'static>,
        name: &str,
        alpn: &[u8],
    ) -> (bool, bool) {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client.alpn_protocols = vec![alpn.to_vec()];
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server = async {
            let mut tls = tokio_rustls::TlsAcceptor::from(configuration)
                .accept(server_io)
                .await?;
            let mut byte = [0];
            tls.read_exact(&mut byte).await?;
            tls.write_all(&byte).await?;
            Ok::<_, std::io::Error>(())
        };
        let client = async {
            let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client))
                .connect(ServerName::try_from(name.to_owned()).unwrap(), client_io)
                .await?;
            tls.write_all(&[42]).await?;
            let mut byte = [0];
            tls.read_exact(&mut byte).await?;
            assert_eq!(byte, [42]);
            Ok::<_, std::io::Error>(())
        };
        let (server, client) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::join!(server, client)
        })
        .await
        .unwrap();
        (server.is_ok(), client.is_ok())
    }

    #[tokio::test]
    async fn admitted_identity_requires_scoped_trust_exact_name_and_http1() {
        let (certificate, key) = root();
        let authority = ConnectAuthority::parse("fixture.test:443").unwrap();
        let server = configuration(certificate.clone(), key, &authority)
            .expect("valid CA could not issue an admitted identity");
        assert_eq!(
            handshake(
                server.clone(),
                certificate.clone(),
                "fixture.test",
                b"http/1.1"
            )
            .await,
            (true, true)
        );
        assert_eq!(
            handshake(
                server.clone(),
                certificate.clone(),
                "other.test",
                b"http/1.1"
            )
            .await,
            (false, false)
        );
        assert_eq!(
            handshake(server.clone(), root().0, "fixture.test", b"http/1.1").await,
            (false, false)
        );
        assert_eq!(
            handshake(server, certificate, "fixture.test", b"h2").await,
            (false, false)
        );
        let (certificate, key) = root();
        let server = configuration(
            certificate.clone(),
            key,
            &ConnectAuthority::parse("127.0.0.1:443").unwrap(),
        )
        .unwrap();
        assert_eq!(
            handshake(server, certificate, "127.0.0.1", b"http/1.1").await,
            (true, true)
        );
    }

    #[test]
    fn invalid_expired_non_ca_and_mismatched_keys_are_rejected() {
        let authority = ConnectAuthority::parse("fixture.test:443").unwrap();
        let (certificate, key) = root();
        assert!(
            configuration(certificate.clone(), key.clone(), &authority).is_ok(),
            "valid CA rejected before negative cases"
        );
        assert!(configuration(certificate.clone(), root().1, &authority).is_err());
        assert!(configuration(certificate, vec![0; 32], &authority).is_err());
        assert!(configuration(vec![0; 32].into(), key, &authority).is_err());
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["fixture.test".into()]).unwrap();
        assert!(
            configuration(
                params.self_signed(&key).unwrap().der().clone(),
                key.serialize_der(),
                &authority
            )
            .is_err()
        );
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.subject_alt_names.clear();
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(2);
        params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        assert!(
            configuration(
                params.self_signed(&key).unwrap().der().clone(),
                key.serialize_der(),
                &authority
            )
            .is_err()
        );
    }
}
