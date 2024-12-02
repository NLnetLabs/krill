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
use crate::{pubd, ta};
use crate::commons::{api, bgp};
use crate::commons::api::{Success, Token};
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
    pub fn get_ok<'a>(
        &self, path: impl IntoIterator<Item = Cow<'a, str>>
    ) -> Result<Success, Error> {
        httpclient::get_ok(
            &self.create_uri(path), Some(&self.token)
        ).map(|_| Success)
    }

    /// Performs a GET request and checks that it gets a 200 OK back.
    pub fn get_ok_quickly<'a>(
        &self, path: impl IntoIterator<Item = Cow<'a, str>>
    ) -> Result<Success, Error> {
        httpclient::get_ok(
            &self.create_uri(path), Some(&self.token)
        ).map(|_| Success)
    }

    /// Performs a GET request expecting a JSON response.
    pub fn get_json<'a, T: DeserializeOwned>(
        &self, path: impl IntoIterator<Item = Cow<'a, str>>
    ) -> Result<T, Error> {
        httpclient::get_json(
            &self.create_uri(path), Some(&self.token)
        )
    }

    /// Performs an empty POST request.
    pub fn post_empty<'a>(
        &self, path: impl IntoIterator<Item = Cow<'a, str>>
    ) -> Result<Success, Error> {
        httpclient::post_empty(
            &self.create_uri(path), Some(&self.token)
        ).map(|_| Success)
    }

    /// Posts JSON-encoded data and expects a JSON-encoded response.
    pub fn post_empty_with_response<'a, T: DeserializeOwned>(
        &self,
        path: impl IntoIterator<Item = Cow<'a, str>>,
    ) -> Result<T, Error> {
        httpclient::post_empty_with_response(
            &self.create_uri(path), Some(&self.token)
        )
    }

    /// Posts JSON-encoded data.
    pub fn post_json<'a>(
        &self,
        path: impl IntoIterator<Item = Cow<'a, str>>,
        data: impl Serialize,
    ) -> Result<Success, Error> {
        httpclient::post_json(
            &self.create_uri(path), data, Some(&self.token)
        ).map(|_| Success)
    }

    /// Posts JSON-encoded data and expects a JSON-encoded response.
    pub fn post_json_with_response<'a, T: DeserializeOwned>(
        &self,
        path: impl IntoIterator<Item = Cow<'a, str>>,
        data: impl Serialize,
    ) -> Result<T, Error> {
        httpclient::post_json_with_response(
            &self.create_uri(path), data, Some(&self.token)
        )
    }

    /// Posts JSON-encoded data and expects an optional JSON-encoded response.
    pub fn post_json_with_opt_response<'a, T: DeserializeOwned>(
        &self,
        path: impl IntoIterator<Item = Cow<'a, str>>,
        data: impl Serialize,
    ) -> Result<Option<T>, Error> {
        httpclient::post_json_with_opt_response(
            &self.create_uri(path), data, Some(&self.token)
        )
    }

    /// Sends a DELETE request.
    pub fn delete<'a>(
        &self, path: impl IntoIterator<Item = Cow<'a, str>>
    ) -> Result<Success, Error> {
        httpclient::delete(
            &self.create_uri(path), Some(&self.token)
        ).map(|_| Success)
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
    pub fn check_running(&self) -> Result<api::Success, Error> {
        self.get_ok_quickly(once("api/v1/authorized"))
    }

    pub fn authorized(&self) -> Result<api::Success, Error> {
        self.get_ok(once("api/v1/authorized"))
    }

    pub fn info(&self) -> Result<api::ServerInfo, Error> {
        self.get_json(once("stats/info"))
    }

    pub fn bulk_issues(&self) -> Result<api::AllCertAuthIssues, Error> {
        self.get_json(once("api/v1/bulk/cas/issues"))
    }

    pub fn bulk_sync_parents(&self) -> Result<api::Success, Error> {
        self.post_empty(once("api/v1/bulk/cas/sync/parent"))
    }

    pub fn bulk_sync_repo(&self) -> Result<api::Success, Error> {
        self.post_empty(once("api/v1/bulk/cas/sync/repo"))
    }

    pub fn bulk_publish(&self) -> Result<api::Success, Error> {
        self.post_empty(once("api/v1/bulk/cas/publish"))
    }

    pub fn bulk_force_publish(&self) -> Result<api::Success, Error> {
        self.post_empty(once("api/v1/bulk/cas/force_publish"))
    }

    pub fn bulk_suspend(&self) -> Result<api::Success, Error> {
        self.post_empty(once("api/v1/bulk/cas/suspend"))
    }

    pub fn bulk_import(
        &self, structure: api::import::Structure
    ) -> Result<api::Success, Error> {
        self.post_json(once("api/v1/bulk/cas/import"), structure)
    }

    pub fn cas_list(&self) -> Result<api::CertAuthList, Error> {
        self.get_json(once("api/v1/cas"))
    }

    pub fn ca_add(&self, ca: CaHandle) -> Result<api::Success, Error> {
        self.post_json(
            once("api/v1/cas"),
            api::CertAuthInit::new(ca)
        )
    }

    pub fn ca_details(
        &self, ca: &CaHandle
    ) -> Result<api::CertAuthInfo, Error> {
        self.get_json(ca_path(ca))
    }

    pub fn ca_delete(
        &self, ca: &CaHandle
    ) -> Result<api::Success, Error> {
        self.delete(ca_path(ca))
    }

    pub fn ca_issues(
        &self, ca: &CaHandle
    ) -> Result<api::CertAuthIssues, Error> {
        self.get_json(ca_path(ca).into_iter().chain(once("issues")))
    }

    pub fn ca_history_commands(
        &self, ca: &CaHandle,
        rows: Option<u64>, offset: Option<u64>,
        after: Option<Time>, before: Option<Time>
    ) -> Result<api::CommandHistory, Error> {
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
        )
    }

    pub fn ca_history_details(
        &self, ca: &CaHandle, key: &str
    ) -> Result<api::CaCommandDetails, Error> {
        self.get_json(
            ca_path(ca).into_iter().chain(
                ["history/details".into(), encode(key)]
            )
        )
    }

    pub fn ca_init_keyroll(
        &self, ca: &CaHandle,
    ) -> Result<api::Success, Error> {
        self.post_empty(
            ca_path(ca).into_iter().chain(once("keys/roll_init"))
        )
    }

    pub fn ca_activate_keyroll(
        &self, ca: &CaHandle,
    ) -> Result<api::Success, Error> {
        self.post_empty(
            ca_path(ca).into_iter().chain(once("keys/roll_activate"))
        )
    }

    pub fn ca_update_id(
        &self, ca: &CaHandle,
    ) -> Result<api::Success, Error> {
        self.post_empty(
            ca_path(ca).into_iter().chain(once("id"))
        )
    }

    pub fn ca_sync_parents(
        &self, ca: &CaHandle,
    ) -> Result<api::Success, Error> {
        self.post_empty(
            ca_path(ca).into_iter().chain(once("sync/parents"))
        )
    }


    pub fn child_connections(
        &self, ca: &CaHandle
    ) -> Result<api::ChildrenConnectionStats, Error> {
        self.get_json(
            ca_path(ca).into_iter().chain(once("stats/children/connections"))
        )
    }

    pub fn child_add(
        &self,
        ca: &CaHandle, child: ChildHandle,
        resources: ResourceSet,
        id_cert: IdCert
    ) -> Result<idexchange::ParentResponse, Error> {
        self.post_json_with_response(
            ca_path(ca).into_iter().chain(once("children")),
            api::AddChildRequest::new(
                child,
                resources,
                id_cert
            )
        )
    }

    pub fn child_import(
        &self, ca: &CaHandle, import: api::import::ImportChild
    ) -> Result<api::Success, Error> {
        self.post_json(
            ca_path(ca).into_iter().chain(
                [
                    "children".into(),
                    encode(import.name.clone().as_str()),
                    "import".into()
                ]
            ),
            import
        )
    }

    pub fn child_details(
        &self, ca: &CaHandle, child: &ChildHandle,
    ) -> Result<api::ChildCaInfo, Error> {
        self.get_json(child_path(ca, child))
    }

    pub fn child_update(
        &self,
        ca: &CaHandle, child: &ChildHandle,
        update: api::UpdateChildRequest
    ) -> Result<api::Success, Error> {
        self.post_json(child_path(ca, child), update)
    }

    pub fn child_contact(
        &self, ca: &CaHandle, child: &ChildHandle,
    ) -> Result<idexchange::ParentResponse, Error> {
        self.get_json(
            child_path(ca, child).into_iter().chain(once("contact"))
        )
    }

    pub fn child_export(
        &self, ca: &CaHandle, child: &ChildHandle,
    ) -> Result<api::import::ExportChild, Error> {
        self.get_json(
            child_path(ca, child).into_iter().chain(once("export"))
        )
    }

    pub fn child_delete(
        &self, ca: &CaHandle, child: &ChildHandle,
    ) -> Result<api::Success, Error> {
        self.delete(child_path(ca, child))
    }

    pub fn child_request(
        &self, ca: &CaHandle
    ) -> Result<idexchange::ChildRequest, Error> {
        self.get_json(
            ca_path(ca).into_iter().chain(once("id/child_request.json"))
        )
    }

    pub fn parent_list(
        &self, ca: &CaHandle,
    ) -> Result<api::ParentStatuses, Error> {
        self.get_json(
            ca_path(ca).into_iter().chain(once("parents")),
        )
    }

    pub fn parent_add(
        &self, ca: &CaHandle, request: api::ParentCaReq,
    ) -> Result<api::Success, Error> {
        self.post_json(
            ca_path(ca).into_iter().chain(once("parents")),
            request,
        )
    }

    pub fn parent_details(
        &self, ca: &CaHandle, parent: &ParentHandle
    ) -> Result<api::ParentCaContact, Error> {
        self.get_json(parent_path(ca, parent))
    }

    pub fn parent_delete(
        &self, ca: &CaHandle, parent: &ParentHandle
    ) -> Result<api::Success, Error> {
        self.delete(parent_path(ca, parent))

    }

    pub fn repo_request(
        &self, ca: &CaHandle,
    ) -> Result<idexchange::PublisherRequest, Error> {
        self.get_json(
            ca_path(ca).into_iter().chain(once("id/publisher_request.json"))
        )
    }

    pub fn repo_details(
        &self, ca: &CaHandle,
    ) -> Result<api::CaRepoDetails, Error> {
        self.get_json(ca_path(ca).into_iter().chain(once("repo")))
    }

    pub fn repo_status(
        &self, ca: &CaHandle,
    ) -> Result<api::RepoStatus, Error> {
        self.get_json(
            ca_path(ca).into_iter().chain(once("repo/status"))
        )
    }

    pub fn repo_update(
        &self, ca: &CaHandle, response: idexchange::RepositoryResponse,
    ) -> Result<api::Success, Error> {
        self.post_json(
            ca_path(ca).into_iter().chain(once("repo")),
            api::ApiRepositoryContact::new(response),
        )
    }

    pub fn roas_list(
        &self, ca: &CaHandle
    ) -> Result<api::ConfiguredRoas, Error> {
        self.get_json(ca_path(ca).into_iter().chain(once("routes")))
    }

    pub fn roas_update(
        &self, ca: &CaHandle, updates: api::RoaConfigurationUpdates
    ) -> Result<api::Success, Error> {
        self.post_json(
            ca_path(ca).into_iter().chain(once("routes")), updates
        )
    }

    pub fn roas_try_update(
        &self, ca: &CaHandle, updates: api::RoaConfigurationUpdates
    ) -> Result<Option<bgp::BgpAnalysisAdvice>, Error> {
        self.post_json_with_opt_response(
            ca_path(ca).into_iter().chain(once("routes/try")), updates
        )
    }

    pub fn roas_dryrun_update(
        &self, ca: &CaHandle, updates: api::RoaConfigurationUpdates
    ) -> Result<bgp::BgpAnalysisReport, Error> {
        self.post_json_with_response(
            ca_path(ca).into_iter().chain(
                once("routes/analysis/dryrun")
            ),
            updates
        )
    }

    pub fn roas_analyze(
        &self, ca: &CaHandle
    ) -> Result<bgp::BgpAnalysisReport, Error> {
        self.get_json(
            ca_path(ca).into_iter().chain(once("routes/analysis/full"))
        )
    }

    pub fn roas_suggest(
        &self, ca: &CaHandle, resources: Option<ResourceSet>
    ) -> Result<bgp::BgpAnalysisSuggestion, Error> {
        match resources {
            Some(resources) => {
                self.post_json_with_response(
                    ca_path(ca).into_iter().chain(
                        once("routes/analysis/suggest")
                    ),
                    resources,
                )
            }
            None => {
                self.get_json(
                    ca_path(ca).into_iter().chain(
                        once("routes/analysis/suggest")
                    )
                )
            }
        }
    }

    pub fn bgpsec_list(
        &self, ca: &CaHandle
    ) -> Result<api::BgpSecCsrInfoList, Error> {
        self.get_json(ca_path(ca).into_iter().chain(once("bgpsec")))
    }

    pub fn bgpsec_update(
        &self, ca: &CaHandle, updates: api::BgpSecDefinitionUpdates
    ) -> Result<api::Success, Error> {
        self.post_json(
            ca_path(ca).into_iter().chain(once("bgpsec")), updates, 
        )
    }

    pub fn bgpsec_add_single(
        &self, ca: &CaHandle, asn: Asn, csr: BgpsecCsr,
    ) -> Result<api::Success, Error> {
        self.bgpsec_update(
            ca,
            api::BgpSecDefinitionUpdates::new(
                vec![api::BgpSecDefinition::new(asn, csr) ], vec![]
            )
        )
    }

    pub fn bgpsec_delete_single(
        &self, ca: &CaHandle, asn: Asn, key: KeyIdentifier,
    ) -> Result<api::Success, Error> {
        self.bgpsec_update(
            ca,
            api::BgpSecDefinitionUpdates::new(
                vec![], vec![api::BgpSecAsnKey::new(asn, key)]
            )
        )
    }

    pub fn aspas_list(
        &self, ca: &CaHandle
    ) -> Result<api::AspaDefinitionList, Error> {
        self.get_json(ca_path(ca).into_iter().chain(once("aspas")))
    }

    pub fn aspas_update(
        &self, ca: &CaHandle, updates: api::AspaDefinitionUpdates,
    ) -> Result<api::Success, Error> {
        self.post_json(
            ca_path(ca).into_iter().chain(once("aspas")), updates
        )
    }

    pub fn aspas_add_single(
        &self, ca: &CaHandle, aspa: api::AspaDefinition
    ) -> Result<api::Success, Error> {
        self.aspas_update(
            ca, api::AspaDefinitionUpdates::new(vec![aspa], vec![])
        )
    }

    pub fn aspas_delete_single(
        &self, ca: &CaHandle, customer: Asn,
    ) -> Result<api::Success, Error> {
        self.aspas_update(
            ca, api::AspaDefinitionUpdates::new(vec![], vec![customer])
        )
    }

    pub fn aspas_update_single(
        &self,
        ca: &CaHandle, customer: Asn,
        update: api::AspaProvidersUpdate
    ) -> Result<api::Success, Error> {
        self.post_json(
            ca_path(ca).into_iter().chain(
                [ "aspas".into(), "as".into(), customer.to_string().into()]),
            update,
        )
    }

    pub fn publishers_list(
        &self
    ) -> Result<api::PublisherList, Error> {
        self.get_json(once("api/v1/pubd/publishers"))
    }

    pub fn publishers_stale(
        &self, seconds: u64,
    ) -> Result<api::PublisherList, Error> {
        self.get_json(
            ["api/v1/pubd/stale".into(), seconds.to_string().into()]
        )
    }

    pub fn publishers_add(
        &self, request: idexchange::PublisherRequest
    ) -> Result<idexchange::RepositoryResponse, Error> {
        self.post_json_with_response(
            once("api/v1/pubd/publishers"),
            request
        )
    }

    pub fn publisher_details(
        &self, publisher: &PublisherHandle
    ) -> Result<api::PublisherDetails, Error> {
        self.get_json(publisher_path(publisher))
    }

    pub fn publisher_response(
        &self, publisher: &PublisherHandle
    ) -> Result<idexchange::RepositoryResponse, Error> {
        self.get_json(
            publisher_path(publisher).into_iter().chain(
                once("response.json")
            )
        )
    }

    pub fn publisher_delete(
        &self, publisher: &PublisherHandle
    ) -> Result<api::Success, Error> {
        self.delete(publisher_path(publisher))
    }

    pub fn pubserver_init(
        &self, rrdp: uri::Https, rsync: uri::Rsync
    ) -> Result<api::Success, Error> {
        self.post_json(
            once("api/v1/pubd/init"),
            api::PublicationServerUris::new(rrdp, rsync)
        )
    }

    pub fn pubserver_delete_files(
        &self, base_uri: uri::Rsync
    ) -> Result<api::Success, Error> {
        self.post_json(
            once("api/v1/pubd/delete"),
            api::RepoFileDeleteCriteria::new(base_uri)
        )
    }

    pub fn pubserver_stats(&self) -> Result<pubd::RepoStats, Error> {
        self.get_json(once("stats/repo"))
    }

    pub fn pubserver_session_reset(
        &self
    ) -> Result<api::Success, Error> {
        self.post_empty(once("api/v1/pubd/session_reset"))
    }

    pub fn pubserver_clear(
        &self
    ) -> Result<api::Success, Error> {
        self.delete(once("api/v1/pubd/init"))
    }
}


/// # Testbed commands
impl KrillClient {
    pub fn testbed_enabled(&self) -> Result<Success, Error> {
        httpclient::get_ok(
            &self.create_uri(once("testbed/enabled")), None
        ).map(|_| Success)
    }

    pub fn testbed_child_add(
        &self,
        child: ChildHandle,
        resources: ResourceSet,
        id_cert: IdCert
    ) -> Result<idexchange::ParentResponse, Error> {
        httpclient::post_json_with_response(
            &self.create_uri(once("testbed/children")),
            api::AddChildRequest::new(child, resources, id_cert),
            None,
        )
    }

    pub fn testbed_child_response(
        &self, child: &ChildHandle,
    ) -> Result<String, Error> {
        httpclient::get_text(
            &self.create_uri([
                "testbed/children".into(),
                encode(child.as_str()),
                "parent_response.xml".into()
            ]),
            None,
        )
    }

    pub fn testbed_child_delete(
        &self, ca: &CaHandle
    ) -> Result<Success, Error> {
        httpclient::delete(
            &self.create_uri(
                ["testbed/children".into(), encode(ca.as_str())]
            ),
            None,
        ).map(|_| Success)
    }

    pub fn testbed_publishers_add(
        &self, request: idexchange::PublisherRequest
    ) -> Result<idexchange::RepositoryResponse, Error> {
        httpclient::post_json_with_response(
            &self.create_uri(once("testbed/publishers")),
            request,
            None,
        )
    }

    pub fn testbed_publisher_delete(
        &self, ca: &CaHandle
    ) -> Result<Success, Error> {
        httpclient::delete(
            &self.create_uri(
                ["testbed/publishers".into(), ca.as_str().into()]
            ),
            None,
        ).map(|_| Success)
    }

    pub fn testbed_tal(&self) -> Result<String, Error> {
        httpclient::get_text(
            &self.create_uri(once("ta/ta.tal")),
            None
        )
    }

    pub fn testbed_renamed_tal(&self) -> Result<String, Error> {
        httpclient::get_text(
            &self.create_uri(once("testbed.tal")),
            None
        )
    }
}

/// # Trust Anchor Proxy commands
impl KrillClient {
    pub fn ta_proxy_init(&self) -> Result<Success, Error> {
        self.post_empty(once("api/v1/ta/proxy/init"))
    }

    pub fn ta_proxy_id(&self) -> Result<api::IdCertInfo, Error> {
        self.get_json(once("api/v1/ta/proxy/id"))
    }

    pub fn ta_proxy_repo_request(
        &self
    ) -> Result<idexchange::PublisherRequest, Error> {
        self.get_json(once("api/v1/ta/proxy/repo/request.json"))
    }

    pub fn ta_proxy_repo_contact(
        &self
    ) -> Result<api::RepositoryContact, Error>  {
        self.get_json(once("api/v1/ta/proxy/repo"))
    }

    pub fn ta_proxy_repo_configure(
        &self, response: idexchange::RepositoryResponse, 
    ) -> Result<Success, Error> {
        self.post_json(
            once("api/v1/ta/proxy/repo"),
            api::ApiRepositoryContact::new(response),
        )
    }

    pub fn ta_proxy_signer_add(
        &self, info: ta::TrustAnchorSignerInfo
    ) -> Result<Success, Error> {
        self.post_json(once("api/v1/ta/proxy/signer/add"), info)
    }

    pub fn ta_proxy_signer_make_request(
        &self
    ) -> Result<ta::TrustAnchorSignedRequest, Error> {
        self.post_empty_with_response(
            once("api/v1/ta/proxy/signer/request")
        )
    }

    pub fn ta_proxy_signer_show_request(
        &self
    ) -> Result<ta::TrustAnchorSignedRequest, Error> {
        self.get_json(once("api/v1/ta/proxy/signer/request"))
    }

    pub fn ta_proxy_signer_response(
        &self, response: ta::TrustAnchorSignedResponse
    ) -> Result<Success, Error> {
        self.post_json(
            once("api/v1/ta/proxy/signer/response"),
            response,
        )
    }

    pub fn ta_proxy_children_add(
        &self, child: api::AddChildRequest,
    ) -> Result<idexchange::ParentResponse, Error> {
        self.post_json_with_response(
            once("api/v1/ta/proxy/children"),
            child,
        )
    }

    pub fn ta_proxy_child_response(
        &self, child: &ChildHandle
    ) -> Result<idexchange::ParentResponse, Error> {
        self.get_json([
            "api/v1/ta/proxy/children".into(),
            encode(child.as_str()),
            "parent_response.json".into(),
        ])
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

