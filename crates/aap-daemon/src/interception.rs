//! Trusted composition only: agent adapters never receive a store handle.
use crate::{DaemonConfig, InterceptionConfiguration};
use aap_http::proxy::{InterceptionIdentity, InterceptionProvider};
use aap_policy::Catalog;
use aap_secrets::{Field, ItemRef, Lease, SecretStore};
use aap_types::{BoxFuture, ErrorCode, Result, proxy::ConnectAuthority};
use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::pki_types::CertificateDer;
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

pub(crate) fn validate(configuration: &DaemonConfig, catalog: &Catalog) -> Result<()> {
    if let Some(ca) = &configuration.interception {
        if ca.credential.store != configuration.store.alias
            || catalog.items.iter().any(|item| {
                item.credential.store == ca.credential.store
                    && item.credential.key == ca.credential.key
            })
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        ItemRef::new(ca.credential.key.clone())?;
        certificate(ca)?;
    }
    Ok(())
}
fn certificate(configuration: &InterceptionConfiguration) -> Result<CertificateDer<'static>> {
    let encoded = &configuration.certificate_der_base64;
    if encoded.len() > 90_000 {
        return Err(ErrorCode::LimitExceeded.into());
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| ErrorCode::RequestInvalid)?;
    if STANDARD.encode(&bytes) != *encoded {
        return Err(ErrorCode::RequestInvalid.into());
    }
    let certificate = CertificateDer::from(bytes);
    aap_transport::interception::certificate_expiry(&certificate)?;
    Ok(certificate)
}

pub(crate) struct StoreInterception {
    store: Arc<dyn SecretStore>,
    reference: ItemRef,
    certificate: CertificateDer<'static>,
    expires: SystemTime,
    slots: Arc<tokio::sync::Semaphore>,
}
impl StoreInterception {
    pub(crate) fn new(
        configuration: &InterceptionConfiguration,
        store: Arc<dyn SecretStore>,
    ) -> Result<Arc<Self>> {
        let certificate = certificate(configuration)?;
        let expires = aap_transport::interception::certificate_expiry(&certificate)?;
        Ok(Arc::new(Self {
            store,
            reference: ItemRef::new(configuration.credential.key.clone())?,
            certificate,
            expires,
            slots: Arc::new(tokio::sync::Semaphore::new(8)),
        }))
    }
}
impl InterceptionProvider for StoreInterception {
    fn issue(
        &self,
        authority: ConnectAuthority,
    ) -> BoxFuture<'_, Result<Arc<dyn InterceptionIdentity>>> {
        Box::pin(async move {
            let permit = self
                .slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| ErrorCode::LimitExceeded)?;
            let metadata = self.store.metadata(&self.reference).await?;
            if metadata.fields != [Field::PrivateKey] {
                return Err(ErrorCode::InspectionUnavailable.into());
            }
            let snapshot = self.store.resolve(&self.reference, &metadata.lease).await?;
            if snapshot.metadata().lease != metadata.lease {
                return Err(ErrorCode::InspectionUnavailable.into());
            }
            let private_key = snapshot.field(Field::PrivateKey)?.expose().to_vec();
            let certificate = self.certificate.clone();
            let deadline = Instant::now() + Duration::from_secs(9 * 60);
            // The permit stays with the blocking job even when its caller drops.
            let configuration = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                aap_transport::interception::configuration(certificate, private_key, &authority)
            })
            .await
            .map_err(|_| ErrorCode::InspectionUnavailable)??;
            let identity = StoreIdentity {
                store: self.store.clone(),
                reference: self.reference.clone(),
                lease: metadata.lease,
                expires: self.expires,
                deadline: metadata
                    .valid_until
                    .map_or(deadline, |until| until.min(deadline)),
                configuration,
            };
            identity.revalidate().await?;
            Ok(Arc::new(identity) as Arc<dyn InterceptionIdentity>)
        })
    }
}
struct StoreIdentity {
    store: Arc<dyn SecretStore>,
    reference: ItemRef,
    lease: Lease,
    expires: SystemTime,
    deadline: Instant,
    configuration: Arc<rustls::ServerConfig>,
}
impl InterceptionIdentity for StoreIdentity {
    fn configuration(&self) -> Arc<rustls::ServerConfig> {
        self.configuration.clone()
    }
    fn revalidate(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            if Instant::now() >= self.deadline || SystemTime::now() >= self.expires {
                return Err(ErrorCode::InspectionUnavailable.into());
            }
            self.store.revalidate(&self.reference, &self.lease).await?;
            Ok(())
        })
    }
}
