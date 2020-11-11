use std::{env, fmt, io};

use serde::de::DeserializeOwned;
use serde::Serialize;

use rpki::uri;

use crate::cli::options::{BulkCaCommand, CaCommand, Command, KrillInitDetails, Options, PublishersCommand};
use crate::cli::report::{ApiResponse, ReportError};
use crate::commons::api::{
    AllCertAuthIssues, CaRepoDetails, CertAuthIssues, ChildCaInfo, ParentCaContact, ParentStatuses, PublisherDetails,
    PublisherList, RepoStatus, Token,
};
use crate::commons::bgp::BgpAnalysisAdvice;
use crate::commons::remote::rfc8183;
use crate::commons::util::{file, httpclient};
use crate::constants::KRILL_CLI_API_ENV;
use crate::daemon::config::Config;

/// Command line tool for Krill admin tasks
pub struct KrillClient {
    server: uri::Https,
    token: Token,
}

impl KrillClient {
    /// Delegates the options to be processed, and reports the response
    /// back to the user. Note that error reporting is handled by CLI.
    pub async fn report(options: Options) -> Result<(), Error> {
        let format = options.format;
        let res = Self::process(options).await?;

        if let Some(string) = res.report(format)? {
            println!("{}", string)
        }
        Ok(())
    }

    /// Processes the options, and returns a response ready for formatting.
    /// Note that this function is public to help integration testing the API
    /// and client.
    pub async fn process(options: Options) -> Result<ApiResponse, Error> {
        let client = KrillClient {
            server: options.server,
            token: options.token,
        };

        if options.api {
            // passing the api option in the env, so that the call
            // to the back-end will just print and exit.
            env::set_var(KRILL_CLI_API_ENV, "1")
        }

        trace!("Sending command: {:?}", options.command);

        match options.command {
            Command::Health => client.health().await,
            Command::Info => client.info().await,
            Command::Bulk(cmd) => client.bulk(cmd).await,
            Command::CertAuth(cmd) => client.certauth(cmd).await,
            Command::Publishers(cmd) => client.publishers(cmd).await,
            Command::Init(details) => client.init(details),
            Command::NotSet => Err(Error::MissingCommand),
        }
    }

    async fn health(&self) -> Result<ApiResponse, Error> {
        httpclient::get_ok(&self.resolve_uri("api/v1/authorized"), Some(&self.token)).await?;
        Ok(ApiResponse::Health)
    }

    async fn info(&self) -> Result<ApiResponse, Error> {
        let info = httpclient::get_json(&self.resolve_uri("stats/info"), Some(&self.token)).await?;
        Ok(ApiResponse::Info(info))
    }

    async fn bulk(&self, command: BulkCaCommand) -> Result<ApiResponse, Error> {
        match command {
            BulkCaCommand::Refresh => {
                self.post_empty("api/v1/bulk/cas/sync/parent").await?;
                Ok(ApiResponse::Empty)
            }
            BulkCaCommand::Publish => {
                self.post_empty("api/v1/bulk/cas/publish").await?;
                Ok(ApiResponse::Empty)
            }
            BulkCaCommand::Sync => {
                self.post_empty("api/v1/bulk/cas/sync/repo").await?;
                Ok(ApiResponse::Empty)
            }
        }
    }

    #[allow(clippy::cognitive_complexity)]
    async fn certauth(&self, command: CaCommand) -> Result<ApiResponse, Error> {
        match command {
            CaCommand::Init(init) => {
                self.post_json("api/v1/cas", init).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::UpdateId(handle) => {
                let uri = format!("api/v1/cas/{}/id", handle);
                self.post_empty(&uri).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::ParentResponse(handle, child) => {
                let uri = format!("api/v1/cas/{}/children/{}/contact", handle, child);
                let info: ParentCaContact = self.get_json(&uri).await?;
                Ok(ApiResponse::ParentCaContact(info))
            }

            CaCommand::ChildRequest(handle) => {
                let uri = format!("api/v1/cas/{}/child_request.json", handle);
                let req = self.get_json(&uri).await?;
                Ok(ApiResponse::Rfc8183ChildRequest(req))
            }

            CaCommand::RepoPublisherRequest(handle) => {
                let uri = format!("api/v1/cas/{}/repo/request.json", handle);
                let req: rfc8183::PublisherRequest = self.get_json(&uri).await?;
                Ok(ApiResponse::Rfc8183PublisherRequest(req))
            }

            CaCommand::RepoDetails(handle) => {
                let uri = format!("api/v1/cas/{}/repo", handle);
                let details: CaRepoDetails = self.get_json(&uri).await?;
                Ok(ApiResponse::RepoDetails(details))
            }

            CaCommand::RepoStatus(ca) => {
                let uri = format!("api/v1/cas/{}/repo/status", ca);
                let status: RepoStatus = self.get_json(&uri).await?;
                Ok(ApiResponse::RepoStatus(status))
            }

            CaCommand::RepoUpdate(handle, update) => {
                let uri = format!("api/v1/cas/{}/repo", handle);
                self.post_json(&uri, update).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::AddParent(handle, parent) => {
                let uri = format!("api/v1/cas/{}/parents", handle);
                self.post_json(&uri, parent).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::UpdateParentContact(handle, parent, contact) => {
                let uri = format!("api/v1/cas/{}/parents/{}", handle, parent);
                self.post_json(&uri, contact).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::RemoveParent(handle, parent) => {
                let uri = format!("api/v1/cas/{}/parents/{}", handle, parent);
                self.delete(&uri).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::ParentStatuses(handle) => {
                let uri = format!("api/v1/cas/{}/parents", handle);
                let statuses: ParentStatuses = self.get_json(&uri).await?;
                Ok(ApiResponse::ParentStatuses(statuses))
            }

            CaCommand::MyParentCaContact(handle, parent) => {
                let uri = format!("api/v1/cas/{}/parents/{}", handle, parent);
                let parent: ParentCaContact = self.get_json(&uri).await?;
                Ok(ApiResponse::ParentCaContact(parent))
            }

            CaCommand::ChildInfo(handle, child) => {
                let uri = format!("api/v1/cas/{}/children/{}", handle, child);
                let info: ChildCaInfo = self.get_json(&uri).await?;
                Ok(ApiResponse::ChildInfo(info))
            }

            CaCommand::ChildAdd(handle, req) => {
                let uri = format!("api/v1/cas/{}/children", handle);
                let info: ParentCaContact = self.post_json_with_response(&uri, req).await?;
                Ok(ApiResponse::ParentCaContact(info))
            }
            CaCommand::ChildUpdate(handle, child, req) => {
                let uri = format!("api/v1/cas/{}/children/{}", handle, child);
                self.post_json(&uri, req).await?;
                Ok(ApiResponse::Empty)
            }
            CaCommand::ChildDelete(handle, child) => {
                let uri = format!("api/v1/cas/{}/children/{}", handle, child);
                self.delete(&uri).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::KeyRollInit(handle) => {
                let uri = format!("api/v1/cas/{}/keys/roll_init", handle);
                self.post_empty(&uri).await?;
                Ok(ApiResponse::Empty)
            }
            CaCommand::KeyRollActivate(handle) => {
                let uri = format!("api/v1/cas/{}/keys/roll_activate", handle);
                self.post_empty(&uri).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::RouteAuthorizationsList(handle) => {
                let uri = format!("api/v1/cas/{}/routes", handle);
                let roas = self.get_json(&uri).await?;
                Ok(ApiResponse::RouteAuthorizations(roas))
            }

            CaCommand::RouteAuthorizationsUpdate(handle, updates) => {
                let uri = format!("api/v1/cas/{}/routes", handle);
                self.post_json(&uri, updates).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::RouteAuthorizationsTryUpdate(handle, updates) => {
                let uri = format!("api/v1/cas/{}/routes/try", handle);
                let advice_opt: Option<BgpAnalysisAdvice> = self.post_json_with_opt_response(&uri, updates).await?;
                match advice_opt {
                    None => Ok(ApiResponse::Empty),
                    Some(advice) => Ok(ApiResponse::BgpAnalysisAdvice(advice)),
                }
            }

            CaCommand::RouteAuthorizationsDryRunUpdate(handle, updates) => {
                let uri = format!("api/v1/cas/{}/routes/analysis/dryrun", handle);
                let report = self.post_json_with_response(&uri, updates).await?;
                Ok(ApiResponse::BgpAnalysisFull(report))
            }

            CaCommand::BgpAnalysisFull(handle) => {
                let uri = format!("api/v1/cas/{}/routes/analysis/full", handle);
                let report = self.get_json(&uri).await?;
                Ok(ApiResponse::BgpAnalysisFull(report))
            }

            CaCommand::BgpAnalysisSuggest(handle, resources) => {
                let uri = format!("api/v1/cas/{}/routes/analysis/suggest", handle);

                let suggestions = if let Some(resources) = resources {
                    self.post_json_with_response(&uri, resources).await?
                } else {
                    self.get_json(&uri).await?
                };

                Ok(ApiResponse::BgpAnalysisSuggestions(suggestions))
            }

            CaCommand::Show(handle) => {
                let uri = format!("api/v1/cas/{}", handle);
                let ca_info = self.get_json(&uri).await?;

                Ok(ApiResponse::CertAuthInfo(ca_info))
            }

            CaCommand::ShowHistory(handle, options) => {
                let uri = format!("api/v1/cas/{}/history/{}", handle, options);
                let history = self.get_json(&uri).await?;

                Ok(ApiResponse::CertAuthHistory(history))
            }

            CaCommand::ShowAction(handle, key) => {
                let uri = format!("api/v1/cas/{}/command/{}", handle, key);
                let action = self.get_json(&uri).await?;

                Ok(ApiResponse::CertAuthAction(action))
            }

            CaCommand::Issues(ca_opt) => match ca_opt {
                Some(ca) => {
                    let uri = format!("api/v1/cas/{}/issues", ca);
                    let issues: CertAuthIssues = self.get_json(&uri).await?;
                    Ok(ApiResponse::CertAuthIssues(issues))
                }
                None => {
                    let issues: AllCertAuthIssues = self.get_json("api/v1/bulk/cas/issues").await?;
                    Ok(ApiResponse::AllCertAuthIssues(issues))
                }
            },

            CaCommand::RtaList(ca) => {
                let uri = format!("api/v1/cas/{}/rta/", ca);
                let list = self.get_json(&uri).await?;
                Ok(ApiResponse::RtaList(list))
            }

            CaCommand::RtaShow(ca, name, out) => {
                let uri = format!("api/v1/cas/{}/rta/{}", ca, name);
                let rta = self.get_json(&uri).await?;

                match out {
                    None => Ok(ApiResponse::Rta(rta)),
                    Some(out) => {
                        file::save(rta.as_ref(), &out)?;
                        Ok(ApiResponse::Empty)
                    }
                }
            }

            CaCommand::RtaSign(ca, name, request) => {
                let uri = format!("api/v1/cas/{}/rta/{}/sign", ca, name);
                self.post_json(&uri, request).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::RtaMultiPrep(ca, name, resources) => {
                let uri = format!("api/v1/cas/{}/rta/{}/multi/prep", ca, name);
                let response = self.post_json_with_response(&uri, resources).await?;
                Ok(ApiResponse::RtaMultiPrep(response))
            }

            CaCommand::RtaMultiCoSign(ca, name, rta) => {
                let uri = format!("api/v1/cas/{}/rta/{}/multi/cosign", ca, name);
                self.post_json(&uri, rta).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::List => {
                let cas = self.get_json("api/v1/cas").await?;
                Ok(ApiResponse::CertAuths(cas))
            }
        }
    }

    async fn publishers(&self, command: PublishersCommand) -> Result<ApiResponse, Error> {
        match command {
            PublishersCommand::PublisherList => {
                let list: PublisherList = self.get_json("api/v1/publishers").await?;
                Ok(ApiResponse::PublisherList(list))
            }
            PublishersCommand::StalePublishers(seconds) => {
                let uri = format!("api/v1/publishers/stale/{}", seconds);
                let stales = self.get_json(&uri).await?;
                Ok(ApiResponse::PublisherList(stales))
            }
            PublishersCommand::Stats => {
                let stats = self.get_json("stats/repo").await?;
                Ok(ApiResponse::RepoStats(stats))
            }
            PublishersCommand::AddPublisher(req) => {
                let res = self.post_json_with_response("api/v1/publishers", req).await?;
                Ok(ApiResponse::Rfc8183RepositoryResponse(res))
            }
            PublishersCommand::RemovePublisher(handle) => {
                let uri = format!("api/v1/publishers/{}", handle);
                self.delete(&uri).await?;
                Ok(ApiResponse::Empty)
            }
            PublishersCommand::ShowPublisher(handle) => {
                let uri = format!("api/v1/publishers/{}", handle);
                let details: PublisherDetails = self.get_json(&uri).await?;
                Ok(ApiResponse::PublisherDetails(details))
            }
            PublishersCommand::RepositoryResponse(handle) => {
                let uri = format!("api/v1/publishers/{}/response.json", handle);
                let res = self.get_json(&uri).await?;
                Ok(ApiResponse::Rfc8183RepositoryResponse(res))
            }
        }
    }

    fn resolve_uri(&self, path: &str) -> String {
        format!("{}{}", &self.server, path)
    }

    fn init(&self, details: KrillInitDetails) -> Result<ApiResponse, Error> {
        let defaults = include_str!("../../defaults/krill.conf");

        let mut config = defaults.to_string();
        config = config.replace("### auth_token =", &format!("auth_token = \"{}\"", self.token));

        config = config.replace(
            "### service_uri = \"https://localhost:3000/\"",
            &format!("service_uri = \"{}\"", self.server),
        );

        if let Some(rsync_base) = details.rsync_base() {
            config = config.replace("### repo_enabled = false", "repo_enabled = true");

            config = config.replace(
                "### rsync_base = \"rsync://localhost/repo/\"",
                &format!("rsync_base = \"{}\"", rsync_base),
            )
        }

        if let Some(rrdp_service_uri) = details.rrdp_service_uri() {
            config = config.replace(
                "### rrdp_service_uri = \"$service_uri/rrdp/\"",
                &format!("rrdp_service_uri = \"{}\"", rrdp_service_uri),
            )
        }

        if let Some(data_dir) = details.data_dir() {
            config = config.replace("### data_dir = \"./data\"", &format!("data_dir = \"{}\"", data_dir))
        }

        if let Some(log_file) = details.log_file() {
            config = config.replace(
                "### log_file = \"./krill.log\"",
                &format!("log_file = \"{}\"", log_file),
            )
        }

        let c: Config = toml::from_slice(config.as_ref()).map_err(Error::init)?;
        c.verify().map_err(Error::init)?;

        Ok(ApiResponse::GenericBody(config))
    }

    async fn get_json<T: DeserializeOwned>(&self, uri: &str) -> Result<T, Error> {
        let uri = self.resolve_uri(uri);
        httpclient::get_json(&uri, Some(&self.token))
            .await
            .map_err(Error::HttpClientError)
    }

    async fn post_empty(&self, uri: &str) -> Result<(), Error> {
        let uri = self.resolve_uri(uri);
        httpclient::post_empty(&uri, Some(&self.token))
            .await
            .map_err(Error::HttpClientError)
    }

    async fn post_json(&self, uri: &str, data: impl Serialize) -> Result<(), Error> {
        let uri = self.resolve_uri(uri);
        httpclient::post_json(&uri, data, Some(&self.token))
            .await
            .map_err(Error::HttpClientError)
    }

    async fn post_json_with_response<T: DeserializeOwned>(&self, uri: &str, data: impl Serialize) -> Result<T, Error> {
        let uri = self.resolve_uri(uri);
        httpclient::post_json_with_response(&uri, data, Some(&self.token))
            .await
            .map_err(Error::HttpClientError)
    }

    async fn post_json_with_opt_response<T: DeserializeOwned>(
        &self,
        uri: &str,
        data: impl Serialize,
    ) -> Result<Option<T>, Error> {
        let uri = self.resolve_uri(uri);
        httpclient::post_json_with_opt_response(&uri, data, Some(&self.token))
            .await
            .map_err(Error::HttpClientError)
    }

    async fn delete(&self, uri: &str) -> Result<(), Error> {
        let uri = self.resolve_uri(uri);
        httpclient::delete(&uri, Some(&self.token))
            .await
            .map_err(Error::HttpClientError)
    }
}

//------------ Error ---------------------------------------------------------

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    MissingCommand,
    ServerDown,
    HttpClientError(httpclient::Error),
    ReportError(ReportError),
    IoError(io::Error),
    EmptyResponse,
    Rfc8183(rfc8183::Error),
    InitError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::MissingCommand => write!(f, "No valid command given, see --help"),
            Error::ServerDown => write!(f, "Server is not available."),
            Error::HttpClientError(e) => write!(f, "Http client error: {}", e),
            Error::ReportError(e) => e.fmt(f),
            Error::IoError(e) => write!(f, "I/O error: {}", e),
            Error::EmptyResponse => write!(f, "Empty response received from server"),
            Error::Rfc8183(e) => e.fmt(f),
            Error::InitError(s) => s.fmt(f),
        }
    }
}

impl Error {
    fn init(msg: impl fmt::Display) -> Self {
        Error::InitError(msg.to_string())
    }
}

impl From<httpclient::Error> for Error {
    fn from(e: httpclient::Error) -> Self {
        Error::HttpClientError(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<ReportError> for Error {
    fn from(e: ReportError) -> Self {
        Error::ReportError(e)
    }
}

impl From<rfc8183::Error> for Error {
    fn from(e: rfc8183::Error) -> Error {
        Error::Rfc8183(e)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use crate::cli::options::KrillInitDetails;
    use crate::test;

    #[test]
    fn init_config_file() {
        let mut details = KrillInitDetails::default();
        details.with_rsync_base(test::rsync("rsync://myhost/repo/"));
        details.with_rrdp_service_uri(test::https("https://myhost/rrdp/"));
        details.with_data_dir("/var/lib/krill/data/");
        details.with_log_file("/var/log/krill/krill.log");

        let client = KrillClient {
            server: test::https("https://localhost:3001/"),
            token: Token::from("secret"),
        };

        let res = client.init(details).unwrap();

        match res {
            ApiResponse::GenericBody(body) => {
                let expected = include_str!("../../test-resources/krill-init.conf");
                assert_eq!(expected, &body)
            }
            _ => panic!("Expected body"),
        }
    }
}
