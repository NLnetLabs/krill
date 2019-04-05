pub mod options;
pub mod report;

use std::io;
use rpki::uri;
use krill_commons::util::file;
use krill_commons::util::httpclient;
use krill_commons::api::admin::{
    PublisherDetails,
    PublisherList,
    PublisherRequest
};
use crate::krillc::report::{
    ApiResponse,
    ReportError
};
use crate::krillc::options::{
    Options,
    Command,
    PublishersCommand
};
use krillc::options::Rfc8181Command;
use krill_cms_proxy::api::{ClientInfo, Token, ClientAuth};
use krill_cms_proxy::rfc8183;

/// Command line tool for Krill admin tasks
pub struct KrillClient {
    server: uri::Http,
    token: String
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
            server: options.server,
            token:  options.token
        };

        match options.command {
            Command::Health => client.health(),
            Command::Publishers(cmd) => client.publishers(cmd),
            Command::Rfc8181(cmd) => client.rfc8181(cmd),
            Command::NotSet => Err(Error::MissingCommand)
        }
    }

    fn health(&self) -> Result<ApiResponse, Error> {
        httpclient::get_ok(
            &self.resolve_uri("api/v1/health"),
            Some(&self.token)
        )?;
        Ok(ApiResponse::Health)
    }

    fn publishers(
        &self,
        command: PublishersCommand,
    ) -> Result<ApiResponse, Error> {
        match command {
            PublishersCommand::List => {
                let list: PublisherList = httpclient::get_json(
                    &self.resolve_uri("api/v1/publishers"),
                    Some(&self.token)
                )?;
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

                let details: PublisherDetails = httpclient::get_json(
                    &uri,
                    Some(&self.token)
                )?;
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
                let list: Vec<ClientInfo> = httpclient::get_json(
                    &uri,
                    Some(&self.token)
                )?;

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

    #[display(fmt="Received invalid json response: {}", _0)]
    JsonError(serde_json::Error),

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

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::JsonError(e)
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

impl From<rfc8183::PublisherRequestError> for Error {
    fn from(e: rfc8183::PublisherRequestError) -> Error {
        Error::PublisherRequestError(e)
    }
}


// Note: this is all tested through integration tests ('tests' folder).