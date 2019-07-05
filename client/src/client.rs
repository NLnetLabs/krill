use std::io;
use rpki::uri;

use serde::de::DeserializeOwned;

use krill_commons::util::file;
use krill_commons::util::httpclient;
use krill_commons::api::admin::{PublisherDetails, PublisherList, PublisherRequest, Token, ParentCaContact};
use krill_commons::api::ca::TrustAnchorInfo;
use krill_cms_proxy::api::{
    ClientAuth,
    ClientInfo,
};
use krill_cms_proxy::rfc8183;

use crate::report::{
    ApiResponse,
    ReportError
};
use crate::options::{
    Options,
    Command,
    PublishersCommand,
    Rfc8181Command,
    TrustAnchorCommand
};
use options::CaCommand;

/// Command line tool for Krill admin tasks
pub struct KrillClient {
    server: uri::Https,
    token: Token,
}

impl KrillClient {

    /// Delegates the options to be processed, and reports the response
    /// back to the user. Note that error reporting is handled by CLI.
    pub fn report(options: Options) -> Result<(), Error> {
        let format = options.format.clone();
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
            server:   options.server,
            token:    options.token,
        };
        match options.command {
            Command::Health => client.health(),
            Command::TrustAnchor(cmd) => client.trustanchor(cmd),
            Command::CertAuth(cmd) => client.certauth(cmd),
            Command::Publishers(cmd) => client.publishers(cmd),
            Command::Rfc8181(cmd) => client.rfc8181(cmd),
            Command::NotSet => Err(Error::MissingCommand)
        }
    }

//    #[cfg(test)]
    pub fn test(options: Options) -> Result<ApiResponse, Error> {
        httpclient::TEST_MODE.with(|m| { *m.borrow_mut() = true; });
        Self::process(options)
    }

    fn health(&self) -> Result<ApiResponse, Error> {
        httpclient::get_ok(
            &self.resolve_uri("api/v1/health"),
            Some(&self.token)
        )?;
        Ok(ApiResponse::Health)
    }

    fn trustanchor(&self, command: TrustAnchorCommand) -> Result<ApiResponse, Error> {
        match command {
            TrustAnchorCommand::Init => {
                let uri = self.resolve_uri("api/v1/trustanchor");
                httpclient::post_empty(&uri, Some(&self.token))?;
                Ok(ApiResponse::Empty)
            },
            TrustAnchorCommand::Show => {
                let uri = self.resolve_uri("api/v1/trustanchor");
                let ta: TrustAnchorInfo  = self.get_json(&uri)?;
                Ok(ApiResponse::TrustAnchorInfo(ta))
            },
            TrustAnchorCommand::Publish => {
                let uri = self.resolve_uri("api/v1/republish");
                httpclient::post_empty(&uri, Some(&self.token))?;
                Ok(ApiResponse::Empty)
            },
            TrustAnchorCommand::AddChild(req) => {
                let uri = self.resolve_uri("api/v1/trustanchor/children");
                let info: ParentCaContact = httpclient::post_json_with_response(
                    &uri, req, Some(&self.token)
                )?;
                Ok(ApiResponse::ParentCaInfo(info))
            }
        }
    }

    fn certauth(&self, command: CaCommand) -> Result<ApiResponse, Error> {
        match command {
            CaCommand::Init(init) => {
                let uri = self.resolve_uri("api/v1/cas");
                httpclient::post_json(&uri, init, Some(&self.token))?;
                Ok(ApiResponse::Empty)
            },
            CaCommand::AddParent(handle, parent) => {
                let uri = format!("api/v1/cas/{}/parents", handle);
                let uri = self.resolve_uri(&uri);
                httpclient::post_json(&uri, parent, Some(&self.token))?;
                Ok(ApiResponse::Empty)
            }
        }
    }

    fn publishers(
        &self,
        command: PublishersCommand,
    ) -> Result<ApiResponse, Error> {
        match command {
            PublishersCommand::List => {
                let list: PublisherList = self.get_json(&self.resolve_uri("api/v1/publishers"))?;
                Ok(ApiResponse::PublisherList(list))
            },
            PublishersCommand::Add(add) => {
                let pbl = PublisherRequest::new(
                    add.handle,
                    add.token,
                    add.base_uri
                );
                self.add_publisher(pbl)
            },
            PublishersCommand::Deactivate(handle) => {
                let uri = format!("api/v1/publishers/{}", handle);
                let uri = self.resolve_uri(&uri);
                httpclient::delete(&uri, Some(&self.token))?;
                Ok(ApiResponse::Empty)
            },
            PublishersCommand::Details(handle) => {
                let uri = format!("api/v1/publishers/{}", handle);
                let uri = self.resolve_uri(&uri);

                let details: PublisherDetails = self.get_json(&uri)?;
                Ok(ApiResponse::PublisherDetails(details))
            },
        }
    }

    fn add_publisher(&self, pbl: PublisherRequest) -> Result<ApiResponse, Error> {
        httpclient::post_json(
            &self.resolve_uri("api/v1/publishers"),
            pbl,
            Some(&self.token)
        )?;

        Ok(ApiResponse::Empty)
    }

    fn rfc8181(&self, command: Rfc8181Command) -> Result<ApiResponse, Error> {
        match command {
            Rfc8181Command::List => {
                let uri = self.resolve_uri("api/v1/rfc8181/clients");
                let list: Vec<ClientInfo> = self.get_json(&uri)?;

                Ok(ApiResponse::Rfc8181ClientList(list))
            },
            Rfc8181Command::Add(details) => {

                let xml = file::read(&details.xml)?;
                let pr = rfc8183::PublisherRequest::decode(xml.as_ref())?;

                let handle = pr.client_handle();

                let id_cert = pr.id_cert().clone();
                let token = Token::from(details.token);
                let auth = ClientAuth::new(id_cert, token);

                let info = ClientInfo::new(handle, auth);

                httpclient::post_json(
                    &self.resolve_uri("api/v1/rfc8181/clients"),
                    info,
                    Some(&self.token)
                )?;

                Ok(ApiResponse::Empty)
            }
        }
    }

    fn resolve_uri(&self, path: &str) -> String {
        format!("{}{}", &self.server, path)
    }

    fn get_json<T: DeserializeOwned>(
        &self,
        uri: &str,
    ) -> Result<T, Error> {
        httpclient::get_json(
            &uri,
            Some(&self.token)
        ).map_err(Error::HttpClientError)
    }
}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt="No valid command given, see --help")]
    MissingCommand,

    #[display(fmt="Server is not available.")]
    ServerDown,

    #[display(fmt="{}", _0)]
    HttpClientError(httpclient::Error),

    #[display(fmt="{}", _0)]
    ReportError(ReportError),

    #[display(fmt="Can't read file: {}", _0)]
    IoError(io::Error),

    #[display(fmt="Empty response received from server")]
    EmptyResponse,

    #[display(fmt="{}", _0)]
    PublisherRequestError(rfc8183::PublisherRequestError)
}

impl From<httpclient::Error> for Error {
    fn from(e: httpclient::Error) -> Self { Error::HttpClientError(e) }
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

impl From<rfc8183::PublisherRequestError> for Error {
    fn from(e: rfc8183::PublisherRequestError) -> Error {
        Error::PublisherRequestError(e)
    }
}