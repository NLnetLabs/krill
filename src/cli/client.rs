//! A client to talk to the Krill server.

use std::borrow::Cow;
use percent_encoding::{CONTROLS, AsciiSet, utf8_percent_encode};
use rpki::uri;
use rpki::crypto::KeyIdentifier;
use rpki::ca::idexchange;
use rpki::ca::csr::BgpsecCsr;
use rpki::ca::idcert::IdCert;
use rpki::ca::idexchange::{
    CaHandle, ChildHandle, ParentHandle, PublisherHandle, ServiceUri
};
use rpki::repository::resources::{Asn, ResourceSet};
use rpki::repository::x509::Time;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use crate::ta;
use crate::api;
use crate::api::admin::Token;
use crate::api::pubd::RepoStats;
use crate::api::status::Success;
use crate::commons::util::httpclient;
use crate::commons::util::httpclient::Error;


//------------ KrillClient ---------------------------------------------------

/// A client to talk to a Krill server.
#[derive(Clone, Debug)]
pub struct KrillClient {
    /// The base URI of the API server.
    base_uri: ServiceUri,

    /// The access token for the API.
    token: Token,
}

/// # Low-level commands
impl KrillClient {
    /// Creates a cient from a URI and token.
    pub fn new(base_uri: ServiceUri, token: Token) -> Self {
        Self { base_uri, token }
    }

    /// Returns the base URI of the server.
    pub fn base_uri(&self) -> &ServiceUri {
        &self.base_uri
    }

    /// Returns the access token.
    pub fn token(&self) -> &Token {
        &self.token
    }

    /// Sets the access token.
    pub fn set_token(&mut self, token: Token) {
        self.token = token
    }

    /// Performs a GET request and checks that it gets a 200 OK back.
    pub async fn get_ok<'a>(
        &self, path: impl IntoIterator<Item = Cow<'a, str>>
    ) -> Result<Success, Error> {
        httpclient::get_ok(
            &self.create_uri(path), Some(&self.token)
        ).await.map(|_| Success)
    }

    /// Performs a GET request expecting a JSON response.
    pub async fn get_json<'a, T: DeserializeOwned>(
        &self, path: impl IntoIterator<Item = Cow<'a, str>>
    ) -> Result<T, Error> {
        httpclient::get_json(
            &self.create_uri(path), Some(&self.token)
        ).await
    }

    /// Performs an empty POST request.
    pub async fn post_empty<'a>(
        &self, path: impl IntoIterator<Item = Cow<'a, str>>
    ) -> Result<Success, Error> {
        httpclient::post_empty(
            &self.create_uri(path), Some(&self.token)
        ).await.map(|_| Success)
    }

    /// Posts JSON-encoded data and expects a JSON-encoded response.
    pub async fn post_empty_with_response<'a, T: DeserializeOwned>(
        &self,
        path: impl IntoIterator<Item = Cow<'a, str>>,
    ) -> Result<T, Error> {
        httpclient::post_empty_with_response(
            &self.create_uri(path), Some(&self.token)
        ).await
    }

    /// Posts JSON-encoded data.
    pub async fn post_json<'a>(
        &self,
        path: impl IntoIterator<Item = Cow<'a, str>>,
        data: impl Serialize,
    ) -> Result<Success, Error> {
        httpclient::post_json(
            &self.create_uri(path), data, Some(&self.token)
        ).await.map(|_| Success)
    }

    /// Posts JSON-encoded data and expects a JSON-encoded response.
    pub async fn post_json_with_response<'a, T: DeserializeOwned>(
        &self,
        path: impl IntoIterator<Item = Cow<'a, str>>,
        data: impl Serialize,
    ) -> Result<T, Error> {
        httpclient::post_json_with_response(
            &self.create_uri(path), data, Some(&self.token)
        ).await
    }

    /// Posts JSON-encoded data and expects an optional JSON-encoded response.
    pub async fn post_json_with_opt_response<'a, T: DeserializeOwned>(
        &self,
        path: impl IntoIterator<Item = Cow<'a, str>>,
        data: impl Serialize,
    ) -> Result<Option<T>, Error> {
        httpclient::post_json_with_opt_response(
            &self.create_uri(path), data, Some(&self.token)
        ).await
    }

    /// Sends a DELETE request.
    pub async fn delete<'a>(
        &self, path: impl IntoIterator<Item = Cow<'a, str>>
    ) -> Result<Success, Error> {
        httpclient::delete(
            &self.create_uri(path), Some(&self.token)
        ).await.map(|_| Success)
    }

    /// Creates the full URI for the HTTP request.
    fn create_uri<'a>(
        &self, path: impl IntoIterator<Item = Cow<'a, str>>
    ) -> String {
        let mut res = String::from(self.base_uri.as_str());
        for item in path {
            if !res.ends_with('/') {
                res.push('/');
            }
            res.push_str(&item);
        }
        res
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
                format!("{}", rows)
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
        httpclient::get_ok(
            &self.create_uri(once("testbed/enabled")), None
        ).await.map(|_| Success)
    }

    pub async fn testbed_child_add(
        &self,
        child: ChildHandle,
        resources: ResourceSet,
        id_cert: IdCert
    ) -> Result<idexchange::ParentResponse, Error> {
        httpclient::post_json_with_response(
            &self.create_uri(once("testbed/children")),
            api::admin::AddChildRequest {
                handle: child, resources, id_cert
            },
            None,
        ).await
    }

    pub async fn testbed_child_response(
        &self, child: &ChildHandle,
    ) -> Result<String, Error> {
        httpclient::get_text(
            &self.create_uri([
                "testbed/children".into(),
                encode(child.as_str()),
                "parent_response.xml".into()
            ]),
            None,
        ).await
    }

    pub async fn testbed_child_delete(
        &self, ca: &CaHandle
    ) -> Result<Success, Error> {
        httpclient::delete(
            &self.create_uri(
                ["testbed/children".into(), encode(ca.as_str())]
            ),
            None,
        ).await.map(|_| Success)
    }

    pub async fn testbed_publishers_add(
        &self, request: idexchange::PublisherRequest
    ) -> Result<idexchange::RepositoryResponse, Error> {
        httpclient::post_json_with_response(
            &self.create_uri(once("testbed/publishers")),
            request,
            None,
        ).await
    }

    pub async fn testbed_publisher_delete(
        &self, ca: &CaHandle
    ) -> Result<Success, Error> {
        httpclient::delete(
            &self.create_uri(
                ["testbed/publishers".into(), ca.as_str().into()]
            ),
            None,
        ).await.map(|_| Success)
    }

    pub async fn testbed_tal(&self) -> Result<String, Error> {
        httpclient::get_text(
            &self.create_uri(once("ta/ta.tal")),
            None
        ).await
    }

    pub async fn testbed_renamed_tal(&self) -> Result<String, Error> {
        httpclient::get_text(
            &self.create_uri(once("testbed.tal")),
            None
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
        &self, info: ta::TrustAnchorSignerInfo
    ) -> Result<Success, Error> {
        self.post_json(once("api/v1/ta/proxy/signer/add"), info).await
    }

    pub async fn ta_proxy_signer_make_request(
        &self
    ) -> Result<ta::TrustAnchorSignedRequest, Error> {
        self.post_empty_with_response(
            once("api/v1/ta/proxy/signer/request")
        ).await
    }

    pub async fn ta_proxy_signer_show_request(
        &self
    ) -> Result<ta::TrustAnchorSignedRequest, Error> {
        self.get_json(once("api/v1/ta/proxy/signer/request")).await
    }

    pub async fn ta_proxy_signer_response(
        &self, response: ta::TrustAnchorSignedResponse
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

