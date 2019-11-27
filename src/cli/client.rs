use std::{env, io};

use serde::de::DeserializeOwned;
use serde::Serialize;

use rpki::uri;

use crate::cli::options::{BulkCaCommand, CaCommand, Command, Options, PublishersCommand};
use crate::cli::report::{ApiResponse, ReportError};
use crate::commons::api::{
    CaRepoDetails, ChildCaInfo, ParentCaContact, PublisherDetails, PublisherList, Token,
};
use crate::commons::remote::rfc8183;
use crate::commons::util::httpclient;
use crate::constants::KRILL_CLI_API_ENV;
use commons::api::CurrentRepoState;

/// Command line tool for Krill admin tasks
pub struct KrillClient {
    server: uri::Https,
    token: Token,
}

impl KrillClient {
    /// Delegates the options to be processed, and reports the response
    /// back to the user. Note that error reporting is handled by CLI.
    pub fn report(options: Options) -> Result<(), Error> {
        let format = options.format;
        let res = Self::process(options)?;

        if let Some(string) = res.report(format)? {
            println!("{}", string)
        }
        Ok(())
    }

    /// Processes the options, and returns a response ready for formatting.
    /// Note that this function is public to help integration testing the API
    /// and client.
    pub fn process(options: Options) -> Result<ApiResponse, Error> {
        let client = KrillClient {
            server: options.server,
            token: options.token,
        };

        if options.api {
            // passing the api option in the env, so that the call
            // to the back-end will just print and exit.
            env::set_var(KRILL_CLI_API_ENV, "1")
        }

        match options.command {
            Command::Health => client.health(),
            Command::Bulk(cmd) => client.bulk(cmd),
            Command::CertAuth(cmd) => client.certauth(cmd),
            Command::Publishers(cmd) => client.publishers(cmd),
            Command::NotSet => Err(Error::MissingCommand),
        }
    }

    fn health(&self) -> Result<ApiResponse, Error> {
        httpclient::get_ok(&self.resolve_uri("api/v1/health"), Some(&self.token))?;
        Ok(ApiResponse::Health)
    }

    fn bulk(&self, command: BulkCaCommand) -> Result<ApiResponse, Error> {
        match command {
            BulkCaCommand::Refresh => {
                self.post_empty("api/v1/cas/refresh_all")?;
                Ok(ApiResponse::Empty)
            }
            BulkCaCommand::Publish => {
                self.post_empty("api/v1/cas/republish_all")?;
                Ok(ApiResponse::Empty)
            }
            BulkCaCommand::Sync => {
                self.post_empty("api/v1/cas/resync_all")?;
                Ok(ApiResponse::Empty)
            }
        }
    }

    fn certauth(&self, command: CaCommand) -> Result<ApiResponse, Error> {
        match command {
            CaCommand::Init(init) => {
                self.post_json("api/v1/cas", init)?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::UpdateId(handle) => {
                let uri = format!("api/v1/cas/{}/id", handle);
                self.post_empty(&uri)?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::ParentResponse(handle, child) => {
                let uri = format!("api/v1/cas/{}/children/{}/contact", handle, child);
                let info: ParentCaContact = self.get_json(&uri)?;
                Ok(ApiResponse::ParentCaContact(info))
            }

            CaCommand::ChildRequest(handle) => {
                let uri = format!("api/v1/cas/{}/child_request.xml", handle);
                let xml = self.get_text(&uri)?;
                let req = rfc8183::ChildRequest::validate(xml.as_bytes())?;
                Ok(ApiResponse::Rfc8183ChildRequest(req))
            }

            CaCommand::RepoPublisherRequest(handle) => {
                let uri = format!("api/v1/cas/{}/repo/request.json", handle);
                let req: rfc8183::PublisherRequest = self.get_json(&uri)?;
                Ok(ApiResponse::Rfc8183PublisherRequest(req))
            }

            CaCommand::RepoDetails(handle) => {
                let uri = format!("api/v1/cas/{}/repo", handle);
                let details: CaRepoDetails = self.get_json(&uri)?;
                Ok(ApiResponse::RepoDetails(details))
            }

            CaCommand::RepoState(handle) => {
                let uri = format!("api/v1/cas/{}/repo/state", handle);
                let state: CurrentRepoState = self.get_json(&uri)?;
                Ok(ApiResponse::RepoState(state))
            }

            CaCommand::RepoUpdate(handle, update) => {
                let uri = format!("api/v1/cas/{}/repo", handle);
                self.post_json(&uri, update)?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::AddParent(handle, parent) => {
                let uri = format!("api/v1/cas/{}/parents", handle);
                self.post_json(&uri, parent)?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::UpdateParentContact(handle, parent, contact) => {
                let uri = format!("api/v1/cas/{}/parents/{}", handle, parent);
                self.post_json(&uri, contact)?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::RemoveParent(handle, parent) => {
                let uri = format!("api/v1/cas/{}/parents/{}", handle, parent);
                self.delete(&uri)?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::MyParentCaContact(handle, parent) => {
                let uri = format!("api/v1/cas/{}/parents/{}", handle, parent);
                let parent: ParentCaContact = self.get_json(&uri)?;
                Ok(ApiResponse::ParentCaContact(parent))
            }

            CaCommand::ChildInfo(handle, child) => {
                let uri = format!("api/v1/cas/{}/children/{}", handle, child);
                let info: ChildCaInfo = self.get_json(&uri)?;
                Ok(ApiResponse::ChildInfo(info))
            }

            CaCommand::ChildAdd(handle, req) => {
                let uri = format!("api/v1/cas/{}/children", handle);
                let info: ParentCaContact = self.post_json_with_response(&uri, req)?;
                Ok(ApiResponse::ParentCaContact(info))
            }
            CaCommand::ChildUpdate(handle, child, req) => {
                let uri = format!("api/v1/cas/{}/children/{}", handle, child);
                self.post_json(&uri, req)?;
                Ok(ApiResponse::Empty)
            }
            CaCommand::ChildDelete(handle, child) => {
                let uri = format!("api/v1/cas/{}/children/{}", handle, child);
                self.delete(&uri)?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::KeyRollInit(handle) => {
                let uri = format!("api/v1/cas/{}/keys/roll_init", handle);
                self.post_empty(&uri)?;
                Ok(ApiResponse::Empty)
            }
            CaCommand::KeyRollActivate(handle) => {
                let uri = format!("api/v1/cas/{}/keys/roll_activate", handle);
                self.post_empty(&uri)?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::RouteAuthorizationsList(handle) => {
                let uri = format!("api/v1/cas/{}/routes", handle);
                let roas = self.get_json(&uri)?;
                Ok(ApiResponse::RouteAuthorizations(roas))
            }

            CaCommand::RouteAuthorizationsUpdate(handle, updates) => {
                let uri = format!("api/v1/cas/{}/routes", handle);
                self.post_json(&uri, updates)?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::Show(handle) => {
                let uri = format!("api/v1/cas/{}", handle);
                let ca_info = self.get_json(&uri)?;

                Ok(ApiResponse::CertAuthInfo(ca_info))
            }

            CaCommand::ShowHistory(handle) => {
                let uri = format!("api/v1/cas/{}/history", handle);
                let history = self.get_json(&uri)?;

                Ok(ApiResponse::CertAuthHistory(history))
            }

            CaCommand::List => {
                let cas = self.get_json("api/v1/cas")?;
                Ok(ApiResponse::CertAuths(cas))
            }
        }
    }

    fn publishers(&self, command: PublishersCommand) -> Result<ApiResponse, Error> {
        match command {
            PublishersCommand::PublisherList => {
                let list: PublisherList = self.get_json("api/v1/publishers")?;
                Ok(ApiResponse::PublisherList(list))
            }
            PublishersCommand::AddPublisher(req) => {
                let res = self.post_json_with_response("api/v1/publishers", req)?;
                Ok(ApiResponse::Rfc8183RepositoryResponse(res))
            }
            PublishersCommand::RemovePublisher(handle) => {
                let uri = format!("api/v1/publishers/{}", handle);
                self.delete(&uri)?;
                Ok(ApiResponse::Empty)
            }
            PublishersCommand::ShowPublisher(handle) => {
                let uri = format!("api/v1/publishers/{}", handle);
                let details: PublisherDetails = self.get_json(&uri)?;
                Ok(ApiResponse::PublisherDetails(details))
            }
            PublishersCommand::RepositiryResponse(handle) => {
                let uri = format!("api/v1/publishers/{}/response.xml", handle);
                let xml = self.get_text(&uri)?;

                let res = rfc8183::RepositoryResponse::validate(xml.as_bytes())?;
                Ok(ApiResponse::Rfc8183RepositoryResponse(res))
            }
        }
    }

    fn resolve_uri(&self, path: &str) -> String {
        format!("{}{}", &self.server, path)
    }

    fn get_text(&self, uri: &str) -> Result<String, Error> {
        let uri = self.resolve_uri(uri);
        httpclient::get_text(&uri, Some(&self.token)).map_err(Error::HttpClientError)
    }

    fn get_json<T: DeserializeOwned>(&self, uri: &str) -> Result<T, Error> {
        let uri = self.resolve_uri(uri);
        httpclient::get_json(&uri, Some(&self.token)).map_err(Error::HttpClientError)
    }

    fn post_empty(&self, uri: &str) -> Result<(), Error> {
        let uri = self.resolve_uri(uri);
        httpclient::post_empty(&uri, Some(&self.token)).map_err(Error::HttpClientError)
    }

    fn post_json(&self, uri: &str, data: impl Serialize) -> Result<(), Error> {
        let uri = self.resolve_uri(uri);
        httpclient::post_json(&uri, data, Some(&self.token)).map_err(Error::HttpClientError)
    }

    fn post_json_with_response<T: DeserializeOwned>(
        &self,
        uri: &str,
        data: impl Serialize,
    ) -> Result<T, Error> {
        let uri = self.resolve_uri(uri);
        httpclient::post_json_with_response(&uri, data, Some(&self.token))
            .map_err(Error::HttpClientError)
    }

    fn delete(&self, uri: &str) -> Result<(), Error> {
        let uri = self.resolve_uri(uri);
        httpclient::delete(&uri, Some(&self.token)).map_err(Error::HttpClientError)
    }
}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "No valid command given, see --help")]
    MissingCommand,

    #[display(fmt = "Server is not available.")]
    ServerDown,

    #[display(fmt = "{}", _0)]
    HttpClientError(httpclient::Error),

    #[display(fmt = "{}", _0)]
    ReportError(ReportError),

    #[display(fmt = "Can't read file: {}", _0)]
    IoError(io::Error),

    #[display(fmt = "Empty response received from server")]
    EmptyResponse,

    #[display(fmt = "{}", _0)]
    Rfc8183(rfc8183::Error),
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
