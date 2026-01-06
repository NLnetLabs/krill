//! HTTP client operations performed by the CA manager.

use bytes::Bytes;
use rpki::ca::idexchange::ServiceUri;
use crate::commons::httpclient;
use crate::commons::KrillResult;
use crate::commons::cmslogger::CmsLogger;
use crate::commons::error::Error;
use crate::server::manager::KrillContext;
use crate::server::runtime::Errand;
use super::CaManager;

//------------ super::CaManager ----------------------------------------------

impl CaManager {
    pub fn post_protocol_cms_binary(
        &self,
        msg: Bytes,
        service_uri: &ServiceUri,
        content_type: &'static str,
        cms_logger: CmsLogger,
        krill: &KrillContext,
    ) -> Errand<(KrillResult<Bytes>, CmsLogger)> {
        let timeout = krill.config().post_protocol_msg_timeout_seconds;
        let service_uri = service_uri.clone(); // XXX This will go away when
                                               //     we rewrite the HTTP
                                               //     client.
        self.runtime.exec(async move || {
            if let Err(err) = cms_logger.sent(&msg) {
                return (Err(Error::from(err)), cms_logger)
            }

            match httpclient::post_binary_with_full_ua(
                service_uri.as_str(),
                &msg,
                content_type,
                timeout,
            ).await {
                Err(err) => {
                    if let Err(err) = cms_logger.err(format!(
                        "Error posting CMS to {service_uri}: {err}"
                    )) {
                        return (Err(Error::from(err)), cms_logger)
                    }
                    (Err(Error::HttpClientError(err)), cms_logger)
                }
                Ok(bytes) => {
                    if let Err(err) = cms_logger.reply(&bytes) {
                        return (Err(Error::from(err)), cms_logger)
                    }
                    (Ok(bytes), cms_logger)
                }
            }
        })
    }
}
