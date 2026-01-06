//! A client to talk to the Krill server.

use std::{env, fmt, process};
use std::borrow::Cow;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use percent_encoding::{CONTROLS, AsciiSet, utf8_percent_encode};
use reqwest::{Response, StatusCode};
use reqwest::header::{CONTENT_TYPE, USER_AGENT, HeaderMap, HeaderValue};
use rpki::uri;
use rpki::crypto::KeyIdentifier;
use rpki::ca::idexchange;
use rpki::ca::csr::BgpsecCsr;
use rpki::ca::idcert::IdCert;
use rpki::ca::idexchange::{
    CaHandle, ChildHandle, ParentHandle, PublisherHandle
};
use rpki::repository::resources::{Asn, ResourceSet};
use rpki::repository::x509::Time;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use crate::api;
use crate::api::admin::Token;
use crate::api::pubd::RepoStats;
use crate::api::status::Success;
use crate::api::ta::{
    ApiTrustAnchorSignedRequest, TrustAnchorSignedResponse,
    TrustAnchorSignerInfo,
};
use crate::commons::file;
use crate::commons::httpclient::Error;
use crate::constants::{
    HTTP_CLIENT_TIMEOUT_SECS, KRILL_CLI_API_ENV, KRILL_HTTPS_ROOT_CERTS_ENV,
};


//------------ KrillClient ---------------------------------------------------

/// A client to talk to a Krill server.
#[derive(Clone, Debug)]
pub struct KrillClient {
    /// The base URI of the API server.
    base_uri: String,

    /// The HTTP client to make the requests. This is stateful.
    http_client: reqwest::Client,

    /// Whether to print the API call and exit.
    report_and_exit: bool,
}

/// # Low-level commands
impl KrillClient {
    /// Creates a cient from a URI and token.
    pub fn new(
        base_uri: ServerUri, token: Option<Token>
    ) -> Result<Self, Error> {
        let mut builder = reqwest::ClientBuilder::new()
            .timeout(Duration::from_secs(HTTP_CLIENT_TIMEOUT_SECS));

        if let Ok(cert_list) = env::var(KRILL_HTTPS_ROOT_CERTS_ENV) {
            for path in cert_list.split(':') {
                let cert = Self::load_root_cert(path)?;
                builder = builder.add_root_certificate(cert);
            }
        }

        let base_uri = match base_uri {
            ServerUri::Http(uri) => {
                // XXX 127.0.0.1 isn’t great. Maybe we should remove this
                //     hidden feature now that we have Unix sockets?
                if uri.starts_with("https://localhost")
                    || uri.starts_with("https://127.0.0.1")
                {
                    builder = builder.danger_accept_invalid_certs(true);
                }
                uri
            }
            #[cfg(unix)]
            ServerUri::Unix(socket_path) => {
                builder = builder.unix_socket(socket_path);
                
                // XXX Do we actually need this if we use an http: base URI?
                builder = builder.danger_accept_invalid_certs(true);

                String::from("http://localhost")
            },
        };

        let mut headers: HeaderMap = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("krill"));

        if let Some(token) = &token {
            headers.insert(
                hyper::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|e| Error::request_build(base_uri.as_str(), e))?
            );
        }

        builder = builder.default_headers(headers);

        let http_client = builder.build().map_err(|e| {
            Error::request_build(base_uri.as_str(), e)
        })?;

        Ok(Self {
            base_uri,
            http_client,
            report_and_exit: env::var(KRILL_CLI_API_ENV).is_ok(),
        })
    }

    /// Returns the base URI of the server.
    pub fn base_uri(&self) -> &str {
        &self.base_uri
    }

    /// Performs a GET request and checks that it gets a 200 OK back.
    pub async fn get_ok<'a>(
        &self, path: impl IntoIterator<Item = Cow<'a, str>>
    ) -> Result<Success, Error> {
        let uri = self.create_uri(path);
        self.report_get(&uri);
        let res = self.http_client.get(&uri).headers(
            Self::headers(None)
        ).send().await.map_err(|e| Error::execute(&uri, e))?;
        Self::opt_text_response(&uri, res).await?;
        Ok(Success)
    }

    /// Performs a GET request expecting a JSON response.
    pub async fn get_json<'a, T: DeserializeOwned>(
        &self, path: impl IntoIterator<Item = Cow<'a, str>>
    ) -> Result<T, Error> {
        let uri = self.create_uri(path);
        self.report_get(&uri);
        let response = self.http_client
            .get(&uri).headers(Self::headers(Some(Self::JSON)))
            .send().await
            .map_err(|e| Error::execute(&uri, e))?;
        Self::process_json_response(&uri, response).await
    }

    pub async fn get_text(
        &self, path: impl IntoIterator<Item = Cow<'_, str>>
    ) -> Result<String, Error> {
        let uri = self.create_uri(path);
        self.report_get(&uri);
        let response = self.http_client
            .get(&uri).headers(Self::headers(Some(Self::JSON)))
            .send().await
            .map_err(|e| Error::execute(&uri, e))?;
        Self::text_response(&uri, response).await
    }

    /// Performs an empty POST request.
    pub async fn post_empty<'a>(
        &self, path: impl IntoIterator<Item = Cow<'a, str>>
    ) -> Result<Success, Error> {
        let uri = self.create_uri(path);
        Self::empty_response(
            &uri, self.do_empty_post(&uri).await?
        ).await
    }

    /// Posts JSON-encoded data and expects a JSON-encoded response.
    pub async fn post_empty_with_response<'a, T: DeserializeOwned>(
        &self,
        path: impl IntoIterator<Item = Cow<'a, str>>,
    ) -> Result<T, Error> {
        let uri = self.create_uri(path);
        Self::process_json_response(
            &uri, self.do_empty_post(&uri).await?
        ).await
    }

    async fn do_empty_post(
        &self,
        uri: &str,
    ) -> Result<Response, Error> {
        self.report_post(uri, None);
        self.http_client.post(uri).headers(
            Self::headers(Some(Self::JSON))
        ).send().await.map_err(|e| Error::execute(uri, e))
    }

    /// Posts JSON-encoded data.
    pub async fn post_json<'a>(
        &self,
        path: impl IntoIterator<Item = Cow<'a, str>>,
        data: impl Serialize,
    ) -> Result<Success, Error> {
        let uri = self.create_uri(path);
        Self::empty_response(
            &uri, self.do_post(&uri, data).await?
        ).await
    }

    /// Posts JSON-encoded data and expects a JSON-encoded response.
    pub async fn post_json_with_response<'a, T: DeserializeOwned>(
        &self,
        path: impl IntoIterator<Item = Cow<'a, str>>,
        data: impl Serialize,
    ) -> Result<T, Error> {
        let uri = self.create_uri(path);
        Self::process_json_response(
            &uri, self.do_post(&uri, data).await?
        ).await
    }

    /// Posts JSON-encoded data and expects an optional JSON-encoded response.
    pub async fn post_json_with_opt_response<'a, T: DeserializeOwned>(
        &self,
        path: impl IntoIterator<Item = Cow<'a, str>>,
        data: impl Serialize,
    ) -> Result<Option<T>, Error> {
        let uri = self.create_uri(path);
        Self::process_opt_json_response(
            &uri, self.do_post(&uri, data).await?
        ).await
    }

    async fn do_post(
        &self,
        uri: &str,
        data: impl Serialize,
    ) -> Result<Response, Error> {
        let body = serde_json::to_string_pretty(&data).map_err(|e| {
            Error::request_build_json(uri, e)
        })?;
        self.report_post(uri, Some(&body));
        self.http_client.post(uri).headers(
            Self::headers(Some(Self::JSON))
        ).body(body).send().await.map_err(|e| Error::execute(uri, e))
    }

    /// Sends a DELETE request.
    pub async fn delete<'a>(
        &self, path: impl IntoIterator<Item = Cow<'a, str>>
    ) -> Result<Success, Error> {
        let uri = self.create_uri(path);
        self.report_delete(&uri);
        let res = self.http_client.delete(&uri).headers(
            Self::headers(None)
        ).send().await.map_err(|e| Error::execute(&uri, e))?;
        match res.status() {
            StatusCode::OK => Ok(Success),
            _ => Err(Error::from_res(&uri, res).await),
        }
    }

    /// Creates the full URI for the HTTP request.
    fn create_uri<'a>(
        &self, path: impl IntoIterator<Item = Cow<'a, str>>
    ) -> String {
        let mut res = String::from(&self.base_uri);
        for item in path {
            if !res.ends_with('/') {
                res.push('/');
            }
            res.push_str(&item);
        }
        res
    }

    #[allow(clippy::result_large_err)]
    fn load_root_cert(
        path_str: &str
    ) -> Result<reqwest::Certificate, Error> {
        let path = PathBuf::from_str(path_str)
            .map_err(|e| Error::request_build_https_cert(path_str, e))?;
        let file = file::read(&path)
            .map_err(|e| Error::request_build_https_cert(path_str, e))?;
        reqwest::Certificate::from_pem(file.as_ref())
            .map_err(|e| Error::request_build_https_cert(path_str, e))
    }
}


/// # High-level commands
///
impl KrillClient {
    pub async fn authorized(&self) -> Result<Success, Error> {
        self.get_ok(once("api/v1/authorized")).await
    }

    pub async fn info(&self) -> Result<api::admin::ServerInfo, Error> {
        self.get_json(once("stats/info")).await
    }

    pub async fn bulk_issues(
        &self
    ) -> Result<api::ca::AllCertAuthIssues, Error> {
        self.get_json(once("api/v1/bulk/cas/issues")).await
    }

    pub async fn bulk_sync_parents(&self) -> Result<Success, Error> {
        self.post_empty(once("api/v1/bulk/cas/sync/parent")).await
    }

    pub async fn bulk_sync_repo(&self) -> Result<Success, Error> {
        self.post_empty(once("api/v1/bulk/cas/sync/repo")).await
    }

    pub async fn bulk_publish(&self) -> Result<Success, Error> {
        self.post_empty(once("api/v1/bulk/cas/publish")).await
    }

    pub async fn bulk_force_publish(&self) -> Result<Success, Error> {
        self.post_empty(once("api/v1/bulk/cas/force_publish")).await
    }

    pub async fn bulk_suspend(&self) -> Result<Success, Error> {
        self.post_empty(once("api/v1/bulk/cas/suspend")).await
    }

    pub async fn bulk_import(
        &self, structure: api::import::Structure
    ) -> Result<Success, Error> {
        self.post_json(once("api/v1/bulk/cas/import"), structure).await
    }

    pub async fn cas_list(&self) -> Result<api::ca::CertAuthList, Error> {
        self.get_json(once("api/v1/cas")).await
    }

    pub async fn ca_add(
        &self, handle: CaHandle
    ) -> Result<Success, Error> {
        self.post_json(
            once("api/v1/cas"),
            api::admin::CertAuthInit { handle }
        ).await
    }

    pub async fn ca_details(
        &self, ca: &CaHandle
    ) -> Result<api::ca::CertAuthInfo, Error> {
        self.get_json(ca_path(ca)).await
    }

    pub async fn ca_delete(
        &self, ca: &CaHandle
    ) -> Result<Success, Error> {
        self.delete(ca_path(ca)).await
    }

    pub async fn ca_issues(
        &self, ca: &CaHandle
    ) -> Result<api::ca::CertAuthIssues, Error> {
        self.get_json(ca_path(ca).into_iter().chain(once("issues"))).await
    }

    pub async fn ca_history_commands(
        &self, ca: &CaHandle,
        rows: Option<u64>, offset: Option<u64>,
        after: Option<Time>, before: Option<Time>
    ) -> Result<api::history::CommandHistory, Error> {
        let path = {
            if let Some(before) = before {
                let after =
                    after.map(|t| t.timestamp()).unwrap_or_else(|| 0);
                format!(
                    "{}/{}/{}/{}",
                    rows.unwrap_or(100),
                    offset.unwrap_or_default(),
                    after,
                    before.timestamp()
                )
            }
            else if let Some(after) = after {
                format!(
                    "{}/{}/{}",
                    rows.unwrap_or(100),
                    offset.unwrap_or_default(),
                    after.timestamp()
                )
            }
            else if let Some(offset) = offset {
                format!("{}/{}", rows.unwrap_or(100), offset)
            }
            else if let Some(rows) = rows {
                format!("{rows}")
            }
            else {
                String::new()
            }
        };
        self.get_json(
            ca_path(ca).into_iter().chain(
                ["history/commands".into(), path.into()]
            )
        ).await
    }

    pub async fn ca_history_details(
        &self, ca: &CaHandle, key: &str
    ) -> Result<api::history::CommandDetails, Error> {
        self.get_json(
            ca_path(ca).into_iter().chain(
                ["history/details".into(), encode(key)]
            )
        ).await
    }

    pub async fn ca_init_keyroll(
        &self, ca: &CaHandle,
    ) -> Result<Success, Error> {
        self.post_empty(
            ca_path(ca).into_iter().chain(once("keys/roll_init"))
        ).await
    }

    pub async fn ca_activate_keyroll(
        &self, ca: &CaHandle,
    ) -> Result<Success, Error> {
        self.post_empty(
            ca_path(ca).into_iter().chain(once("keys/roll_activate"))
        ).await
    }

    pub async fn ca_update_id(
        &self, ca: &CaHandle,
    ) -> Result<Success, Error> {
        self.post_empty(
            ca_path(ca).into_iter().chain(once("id"))
        ).await
    }

    pub async fn ca_sync_parents(
        &self, ca: &CaHandle,
    ) -> Result<Success, Error> {
        self.post_empty(
            ca_path(ca).into_iter().chain(once("sync/parents"))
        ).await
    }


    pub async fn child_connections(
        &self, ca: &CaHandle
    ) -> Result<api::ca::ChildrenConnectionStats, Error> {
        self.get_json(
            ca_path(ca).into_iter().chain(once("stats/children/connections"))
        ).await
    }

    pub async fn child_add(
        &self,
        ca: &CaHandle, child: ChildHandle,
        resources: ResourceSet,
        id_cert: IdCert
    ) -> Result<idexchange::ParentResponse, Error> {
        self.post_json_with_response(
            ca_path(ca).into_iter().chain(once("children")),
            api::admin::AddChildRequest {
                handle: child,
                resources,
                id_cert
            }
        ).await
    }

    pub async fn child_import(
        &self, ca: &CaHandle, import: api::import::ImportChild
    ) -> Result<Success, Error> {
        self.post_json(
            ca_path(ca).into_iter().chain(
                [
                    "children".into(),
                    encode(import.name.clone().as_str()),
                    "import".into()
                ]
            ),
            import
        ).await
    }

    pub async fn child_details(
        &self, ca: &CaHandle, child: &ChildHandle,
    ) -> Result<api::ca::ChildCaInfo, Error> {
        self.get_json(child_path(ca, child)).await
    }

    pub async fn child_update(
        &self,
        ca: &CaHandle, child: &ChildHandle,
        update: api::admin::UpdateChildRequest
    ) -> Result<Success, Error> {
        self.post_json(child_path(ca, child), update).await
    }

    pub async fn child_contact(
        &self, ca: &CaHandle, child: &ChildHandle,
    ) -> Result<idexchange::ParentResponse, Error> {
        self.get_json(
            child_path(ca, child).into_iter().chain(once("contact"))
        ).await
    }

    pub async fn child_export(
        &self, ca: &CaHandle, child: &ChildHandle,
    ) -> Result<api::import::ImportChild, Error> {
        self.get_json(
            child_path(ca, child).into_iter().chain(once("export"))
        ).await
    }

    pub async fn child_delete(
        &self, ca: &CaHandle, child: &ChildHandle,
    ) -> Result<Success, Error> {
        self.delete(child_path(ca, child)).await
    }

    pub async fn child_request(
        &self, ca: &CaHandle
    ) -> Result<idexchange::ChildRequest, Error> {
        self.get_json(
            ca_path(ca).into_iter().chain(once("id/child_request.json"))
        ).await
    }

    pub async fn parent_list(
        &self, ca: &CaHandle,
    ) -> Result<api::ca::ParentStatuses, Error> {
        self.get_json(
            ca_path(ca).into_iter().chain(once("parents")),
        ).await
    }

    pub async fn parent_add(
        &self, ca: &CaHandle, request: api::admin::ParentCaReq,
    ) -> Result<Success, Error> {
        self.post_json(
            ca_path(ca).into_iter().chain(once("parents")),
            request,
        ).await
    }

    pub async fn parent_details(
        &self, ca: &CaHandle, parent: &ParentHandle
    ) -> Result<api::admin::ParentCaContact, Error> {
        self.get_json(parent_path(ca, parent)).await
    }

    pub async fn parent_delete(
        &self, ca: &CaHandle, parent: &ParentHandle
    ) -> Result<Success, Error> {
        self.delete(parent_path(ca, parent)).await

    }

    pub async fn repo_request(
        &self, ca: &CaHandle,
    ) -> Result<idexchange::PublisherRequest, Error> {
        self.get_json(
            ca_path(ca).into_iter().chain(once("id/publisher_request.json"))
        ).await
    }

    pub async fn repo_details(
        &self, ca: &CaHandle,
    ) -> Result<api::ca::CaRepoDetails, Error> {
        self.get_json(ca_path(ca).into_iter().chain(once("repo"))).await
    }

    pub async fn repo_status(
        &self, ca: &CaHandle,
    ) -> Result<api::ca::RepoStatus, Error> {
        self.get_json(
            ca_path(ca).into_iter().chain(once("repo/status"))
        ).await
    }

    pub async fn repo_update(
        &self,
        ca: &CaHandle,
        repository_response: idexchange::RepositoryResponse,
    ) -> Result<Success, Error> {
        self.post_json(
            ca_path(ca).into_iter().chain(once("repo")),
            api::admin::ApiRepositoryContact { repository_response },
        ).await
    }

    pub async fn roas_list(
        &self, ca: &CaHandle
    ) -> Result<api::roa::ConfiguredRoas, Error> {
        self.get_json(ca_path(ca).into_iter().chain(once("routes"))).await
    }

    pub async fn roas_update(
        &self, ca: &CaHandle, updates: api::roa::RoaConfigurationUpdates
    ) -> Result<Success, Error> {
        self.post_json(
            ca_path(ca).into_iter().chain(once("routes")), updates
        ).await
    }

    pub async fn roas_try_update(
        &self, ca: &CaHandle, updates: api::roa::RoaConfigurationUpdates
    ) -> Result<Option<api::bgp::BgpAnalysisAdvice>, Error> {
        self.post_json_with_opt_response(
            ca_path(ca).into_iter().chain(once("routes/try")), updates
        ).await
    }

    pub async fn roas_dryrun_update(
        &self, ca: &CaHandle, updates: api::roa::RoaConfigurationUpdates
    ) -> Result<api::bgp::BgpAnalysisReport, Error> {
        self.post_json_with_response(
            ca_path(ca).into_iter().chain(
                once("routes/analysis/dryrun")
            ),
            updates
        ).await
    }

    pub async fn roas_analyze(
        &self, ca: &CaHandle
    ) -> Result<api::bgp::BgpAnalysisReport, Error> {
        self.get_json(
            ca_path(ca).into_iter().chain(once("routes/analysis/full"))
        ).await
    }

    pub async fn roas_suggest(
        &self, ca: &CaHandle, resources: Option<ResourceSet>
    ) -> Result<api::bgp::BgpAnalysisSuggestion, Error> {
        match resources {
            Some(resources) => {
                self.post_json_with_response(
                    ca_path(ca).into_iter().chain(
                        once("routes/analysis/suggest")
                    ),
                    resources,
                ).await
            }
            None => {
                self.get_json(
                    ca_path(ca).into_iter().chain(
                        once("routes/analysis/suggest")
                    )
                ).await
            }
        }
    }

    pub async fn bgpsec_list(
        &self, ca: &CaHandle
    ) -> Result<api::bgpsec::BgpSecCsrInfoList, Error> {
        self.get_json(ca_path(ca).into_iter().chain(once("bgpsec"))).await
    }

    pub async fn bgpsec_update(
        &self, ca: &CaHandle, updates: api::bgpsec::BgpSecDefinitionUpdates
    ) -> Result<Success, Error> {
        self.post_json(
            ca_path(ca).into_iter().chain(once("bgpsec")), updates, 
        ).await
    }

    pub async fn bgpsec_add_single(
        &self, ca: &CaHandle, asn: Asn, csr: BgpsecCsr,
    ) -> Result<Success, Error> {
        self.bgpsec_update(
            ca,
            api::bgpsec::BgpSecDefinitionUpdates {
                add: vec![api::bgpsec::BgpSecDefinition { asn, csr } ],
                remove: Vec::new(),
            }
        ).await
    }

    pub async fn bgpsec_delete_single(
        &self, ca: &CaHandle, asn: Asn, key: KeyIdentifier,
    ) -> Result<Success, Error> {
        self.bgpsec_update(
            ca,
            api::bgpsec::BgpSecDefinitionUpdates {
                add: Vec::new(),
                remove: vec![api::bgpsec::BgpSecAsnKey { asn, key }],
            }
        ).await
    }

    pub async fn aspas_list(
        &self, ca: &CaHandle
    ) -> Result<api::aspa::AspaDefinitionList, Error> {
        self.get_json(ca_path(ca).into_iter().chain(once("aspas"))).await
    }

    pub async fn aspas_update(
        &self, ca: &CaHandle, updates: api::aspa::AspaDefinitionUpdates,
    ) -> Result<Success, Error> {
        self.post_json(
            ca_path(ca).into_iter().chain(once("aspas")), updates
        ).await
    }

    pub async fn aspas_add_single(
        &self, ca: &CaHandle, aspa: api::aspa::AspaDefinition
    ) -> Result<Success, Error> {
        self.aspas_update(
            ca,
            api::aspa::AspaDefinitionUpdates {
                add_or_replace: vec![aspa],
                remove: Vec::new(),
            }
        ).await
    }

    pub async fn aspas_delete_single(
        &self, ca: &CaHandle, customer: Asn,
    ) -> Result<Success, Error> {
        self.aspas_update(
            ca,
            api::aspa::AspaDefinitionUpdates {
                add_or_replace: Vec::new(),
                remove: vec![customer]
            }
        ).await
    }

    pub async fn aspas_update_single(
        &self,
        ca: &CaHandle, customer: Asn,
        update: api::aspa::AspaProvidersUpdate
    ) -> Result<Success, Error> {
        self.post_json(
            ca_path(ca).into_iter().chain(
                [ "aspas".into(), "as".into(), customer.to_string().into()]),
            update,
        ).await
    }

    pub async fn publishers_list(
        &self
    ) -> Result<api::admin::PublisherList, Error> {
        self.get_json(once("api/v1/pubd/publishers")).await
    }

    pub async fn publishers_stale(
        &self, seconds: u64,
    ) -> Result<api::admin::PublisherList, Error> {
        self.get_json(
            ["api/v1/pubd/stale".into(), seconds.to_string().into()]
        ).await
    }

    pub async fn publishers_add(
        &self, request: idexchange::PublisherRequest
    ) -> Result<idexchange::RepositoryResponse, Error> {
        self.post_json_with_response(
            once("api/v1/pubd/publishers"),
            request
        ).await
    }

    pub async fn publisher_details(
        &self, publisher: &PublisherHandle
    ) -> Result<api::admin::PublisherDetails, Error> {
        self.get_json(publisher_path(publisher)).await
    }

    pub async fn publisher_response(
        &self, publisher: &PublisherHandle
    ) -> Result<idexchange::RepositoryResponse, Error> {
        self.get_json(
            publisher_path(publisher).into_iter().chain(
                once("response.json")
            )
        ).await
    }

    pub async fn publisher_delete(
        &self, publisher: &PublisherHandle
    ) -> Result<Success, Error> {
        self.delete(publisher_path(publisher)).await
    }

    pub async fn pubserver_init(
        &self, rrdp: uri::Https, rsync: uri::Rsync
    ) -> Result<Success, Error> {
        self.post_json(
            once("api/v1/pubd/init"),
            api::admin::PublicationServerUris {
                rrdp_base_uri: rrdp,
                rsync_jail: rsync
            },
        ).await
    }

    pub async fn pubserver_delete_files(
        &self, base_uri: uri::Rsync
    ) -> Result<Success, Error> {
        self.post_json(
            once("api/v1/pubd/delete"),
            api::admin::RepoFileDeleteCriteria { base_uri }
        ).await
    }

    pub async fn pubserver_stats(&self) -> Result<RepoStats, Error> {
        self.get_json(once("stats/repo")).await
    }

    pub async fn pubserver_session_reset(
        &self
    ) -> Result<Success, Error> {
        self.post_empty(once("api/v1/pubd/session_reset")).await
    }

    pub async fn pubserver_clear(
        &self
    ) -> Result<Success, Error> {
        self.delete(once("api/v1/pubd/init")).await
    }
}


/// # Testbed commands
impl KrillClient {
    pub async fn testbed_enabled(&self) -> Result<Success, Error> {
        self.get_ok(once("testbed/enabled")).await
    }

    pub async fn testbed_child_add(
        &self,
        child: ChildHandle,
        resources: ResourceSet,
        id_cert: IdCert
    ) -> Result<idexchange::ParentResponse, Error> {
        self.post_json_with_response(
            once("testbed/children"),
            api::admin::AddChildRequest {
                handle: child, resources, id_cert
            }
        ).await
    }

    pub async fn testbed_child_response(
        &self, child: &ChildHandle,
    ) -> Result<String, Error> {
        self.get_text(
            [
                "testbed/children".into(),
                encode(child.as_str()),
                "parent_response.xml".into()
            ],
        ).await
    }

    pub async fn testbed_child_delete(
        &self, ca: &CaHandle
    ) -> Result<Success, Error> {
        self.delete(
            ["testbed/children".into(), encode(ca.as_str())]
        ).await.map(|_| Success)
    }

    pub async fn testbed_publishers_add(
        &self, request: idexchange::PublisherRequest
    ) -> Result<idexchange::RepositoryResponse, Error> {
        self.post_json_with_response(
            once("testbed/publishers"),
            request,
        ).await
    }

    pub async fn testbed_publisher_delete(
        &self, ca: &CaHandle
    ) -> Result<Success, Error> {
        self.delete(
            ["testbed/publishers".into(), ca.as_str().into()]
        ).await.map(|_| Success)
    }

    pub async fn testbed_tal(&self) -> Result<String, Error> {
        self.get_text(
            once("ta/ta.tal"),
        ).await
    }

    pub async fn testbed_renamed_tal(&self) -> Result<String, Error> {
        self.get_text(
            once("testbed.tal"),
        ).await
    }
}

/// # Trust Anchor Proxy commands
impl KrillClient {
    pub async fn ta_proxy_init(&self) -> Result<Success, Error> {
        self.post_empty(once("api/v1/ta/proxy/init")).await
    }

    pub async fn ta_proxy_id(&self) -> Result<api::ca::IdCertInfo, Error> {
        self.get_json(once("api/v1/ta/proxy/id")).await
    }

    pub async fn ta_proxy_repo_request(
        &self
    ) -> Result<idexchange::PublisherRequest, Error> {
        self.get_json(once("api/v1/ta/proxy/repo/request.json")).await
    }

    pub async fn ta_proxy_repo_contact(
        &self
    ) -> Result<api::admin::RepositoryContact, Error>  {
        self.get_json(once("api/v1/ta/proxy/repo")).await
    }

    pub async fn ta_proxy_repo_configure(
        &self, repository_response: idexchange::RepositoryResponse, 
    ) -> Result<Success, Error> {
        self.post_json(
            once("api/v1/ta/proxy/repo"),
            api::admin::ApiRepositoryContact { repository_response },
        ).await
    }

    pub async fn ta_proxy_signer_add(
        &self, info: TrustAnchorSignerInfo
    ) -> Result<Success, Error> {
        self.post_json(once("api/v1/ta/proxy/signer/add"), info).await
    }

    pub async fn ta_proxy_signer_update(
        &self, info: TrustAnchorSignerInfo
    ) -> Result<Success, Error> {
        self.post_json(once("api/v1/ta/proxy/signer/update"), info).await
    }

    pub async fn ta_proxy_signer_make_request(
        &self
    ) -> Result<ApiTrustAnchorSignedRequest, Error> {
        self.post_empty_with_response(
            once("api/v1/ta/proxy/signer/request")
        ).await
    }

    pub async fn ta_proxy_signer_show_request(
        &self
    ) -> Result<ApiTrustAnchorSignedRequest, Error> {
        self.get_json(once("api/v1/ta/proxy/signer/request")).await
    }

    pub async fn ta_proxy_signer_response(
        &self, response: TrustAnchorSignedResponse
    ) -> Result<Success, Error> {
        self.post_json(
            once("api/v1/ta/proxy/signer/response"),
            response,
        ).await
    }

    pub async fn ta_proxy_children_add(
        &self, child: api::admin::AddChildRequest,
    ) -> Result<idexchange::ParentResponse, Error> {
        self.post_json_with_response(
            once("api/v1/ta/proxy/children"),
            child,
        ).await
    }

    pub async fn ta_proxy_child_response(
        &self, child: &ChildHandle
    ) -> Result<idexchange::ParentResponse, Error> {
        self.get_json([
            "api/v1/ta/proxy/children".into(),
            encode(child.as_str()),
            "parent_response.json".into(),
        ]).await
    }
}


/// # Very-low level commands
///
impl KrillClient {
    const JSON: &str = "application/json";

    fn report_get(&self, uri: &str) {
        if self.report_and_exit {
            println!("GET:\n  {uri}");
            process::exit(0);
        }
    }

    fn report_post(
        &self, uri: &str, body: Option<&str>,
    ) {
        if self.report_and_exit {
            println!("POST:\n  {uri}");
            if let Some(body) = body {
                println!("Body:\n{body}");
            }
            std::process::exit(0);
        }
    }

    fn report_delete(&self, uri: &str) {
        if self.report_and_exit {
            println!("DELETE:\n  {uri}");
            std::process::exit(0);
        }
    }

    fn headers(content_type: Option<&'static str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("krill"));
        if let Some(content_type) = content_type {
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static(content_type)
            );
        }
        headers
    }

    async fn process_json_response<T: DeserializeOwned>(
        uri: &str,
        res: Response,
    ) -> Result<T, Error> {
        match Self::process_opt_json_response(uri, res).await? {
            None => Err(Error::response(uri, "got empty response body")),
            Some(res) => Ok(res),
        }
    }

    async fn process_opt_json_response<T: DeserializeOwned>(
        uri: &str,
        res: Response,
    ) -> Result<Option<T>, Error> {
        match Self::opt_text_response(uri, res).await? {
            None => Ok(None),
            Some(s) => {
                let res: T = serde_json::from_str(&s).map_err(|e| {
                    Error::response(
                        uri,
                        format!("could not parse JSON response: {e}"),
                    )
                })?;
                Ok(Some(res))
            }
        }
    }

    async fn empty_response(
        uri: &str, res: Response
    ) -> Result<Success, Error> {
        match Self::opt_text_response(uri, res).await? {
            None => Ok(Success),
            Some(_) => Err(Error::response(uri, "expected empty response")),
        }
    }

    async fn text_response(
        uri: &str, res: Response
    ) -> Result<String, Error> {
        match Self::opt_text_response(uri, res).await? {
            None => Err(Error::response(uri, "expected response body")),
            Some(s) => Ok(s),
        }
    }

    async fn opt_text_response(
        uri: &str,
        res: Response,
    ) -> Result<Option<String>, Error> {
        match res.status() {
            StatusCode::OK => match res.text().await.ok() {
                None => Ok(None),
                Some(s) => {
                    if s.is_empty() {
                        Ok(None)
                    } else {
                        Ok(Some(s))
                    }
                }
            },
            StatusCode::FORBIDDEN => Err(Error::Forbidden(uri.to_string())),
            _ => Err(Error::from_res(uri, res).await),
        }
    }
}


//------------ ServerUri -----------------------------------------------------

/// The URI to connect to the Krill server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerUri {
    /// A HTTP or HTTPS URI.
    ///
    /// The value is the URI including the scheme.
    Http(String),

    /// A URI for a Unix socket.
    ///
    /// The contained value is the path of the socket.
    #[cfg(unix)]
    Unix(PathBuf),
}

impl TryFrom<String> for ServerUri {
    type Error = &'static str;

    fn try_from(mut value: String) -> Result<Self, Self::Error> {
        // Check for a four-character scheme.
        if let Some(scheme) = value.as_bytes().get(0..7) {
            if scheme.eq_ignore_ascii_case(b"http://") {
                return Ok(Self::Http(value))
            }
            #[cfg(unix)]
            if scheme.eq_ignore_ascii_case(b"unix://") {
                return Ok(Self::Unix(value.split_off(7).into()))
            }
        }

        // Check for a five-character scheme.
        if let Some(scheme) = value.as_bytes().get(0..8) {
            if scheme.eq_ignore_ascii_case(b"https://") {
                return Ok(Self::Http(value))
            }
        }

        Err("unsupported URI scheme")
    }
}

impl FromStr for ServerUri {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(String::from(value))
    }
}

impl fmt::Display for ServerUri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Http(string) => string.fmt(f),
            #[cfg(unix)]
            Self::Unix(path) => {
                write!(f, "unix://{}", path.display())
            }
        }
    }
}


//------------ Path Helpers --------------------------------------------------

fn ca_path(ca: &CaHandle) -> impl IntoIterator<Item = Cow<'_, str>> {
    ["api/v1/cas".into(), encode(ca.as_str())]
}

fn child_path<'s>(
    ca: &'s CaHandle, child: &'s ChildHandle
) -> impl IntoIterator<Item = Cow<'s, str>> {
    ca_path(ca).into_iter().chain(["children".into(), encode(child.as_str())])
}

fn parent_path<'s>(
    ca: &'s CaHandle, parent: &'s ParentHandle
) -> impl IntoIterator<Item = Cow<'s, str>> {
    ca_path(ca).into_iter().chain(["parents".into(), encode(parent.as_str())])
}

fn publisher_path(
    publisher: &PublisherHandle
) -> impl IntoIterator<Item = Cow<'_, str>> {
    ["api/v1/pubd/publishers".into(), encode(publisher.as_str())]
}

fn once(s: &str) -> impl Iterator<Item = Cow<'_, str>> {
    std::iter::once(s.into())
}

/// The set of ASCII characters that needs percent encoding in a path.
///
/// RFC 3986 defines the characters that do _not_ need encoding:
///
/// ```text
/// pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
/// unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
/// sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
///                 / "*" / "+" / "," / ";" / "="
/// ```
///
/// XXX Someone please double-check this.
const PATH_ENCODE_SET: &AsciiSet =
    &CONTROLS
    .add(b' ').add(b'"').add(b'#').add(b'%').add(b'/').add(b'<').add(b'>')
    .add(b'?').add(b'[').add(b'\\').add(b']').add(b'^').add(b'`').add(b'{')
    .add(b'|').add(b'}').add(b'\x7f');

fn encode(s: &str) -> Cow<'_, str> {
    utf8_percent_encode(s, PATH_ENCODE_SET).into()
}

