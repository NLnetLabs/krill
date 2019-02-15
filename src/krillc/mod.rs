pub mod data;
pub mod options;

use std::io;
use bytes::Bytes;
use rpki::uri;
use crate::api::publisher_data::PublisherRequest;
use crate::krillc::data::{
    ApiResponse,
    PublisherDetails,
    PublisherList,
    ReportError
};
use crate::krillc::options::{
    Options,
    Command,
    PublishersCommand
};
use crate::remote::rfc8183;
use crate::util::file;
use crate::util::httpclient;

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
                    add.base_uri,
                    None
                );
                self.add_publisher(pbl)
            },
            PublishersCommand::AddWithCms(add) => {
                let bytes = file::read(&add.xml)?;
                let pr = rfc8183::PublisherRequest::decode(bytes.as_ref())?;
                let pbl = pr.into_publisher(add.token, add.base_uri);

                self.add_publisher(pbl)
            },
            PublishersCommand::Remove(handle) => {
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
            PublishersCommand::RepositoryResponseXml(handle, file_opt) => {
                let uri = format!("api/v1/publishers/{}/response.xml", handle);
                let uri = self.resolve_uri(&uri);

                let xml = httpclient::get_text(
                    &uri,
                    "application/xml",
                    Some(&self.token)
                )?;

                match file_opt {
                    Some(path) => {
                        file::save(&Bytes::from(xml), &path)?;
                        Ok(ApiResponse::Empty)
                    },
                    None => {
                        Ok(ApiResponse::GenericBody(xml))
                    }
                }
            },
            PublishersCommand::IdCert(handle, file) => {
                let uri = format!("api/v1/publishers/{}", handle);
                let uri = self.resolve_uri(&uri);

                let details: PublisherDetails = httpclient::get_json(
                    &uri,
                    Some(&self.token)
                )?;

                match details.identity_cert() {
                    Some(cert) => {
                        let bytes = cert.to_bytes();
                        file::save(&bytes, &file)?;
                        Ok(ApiResponse::Empty)
                    },
                    None => Err(Error::NoIdCert)
                }
            }
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

    #[display(fmt="There is no known IdCert for this publisher")]
    NoIdCert,

    #[display(fmt="Invalid RFC8183 XML")]
    InvalidRfc8183,

    #[display(fmt="Empty response received from server")]
    EmptyResponse
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
    fn from(_e: rfc8183::PublisherRequestError) -> Error {
        Error::InvalidRfc8183
    }
}


// Note: this is all tested through integration tests ('tests' folder).