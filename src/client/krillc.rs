use std::io;
use std::time::Duration;
use bytes::Bytes;
use rpki::uri;
use reqwest::{Client, StatusCode};
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use crate::client::data::{
    ApiResponse,
    PublisherDetails,
    PublisherList,
    ReportError
};
use crate::client::options::{
    Options,
    Command,
    PublishersCommand
};
use crate::util::file;
use reqwest::Response;

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
        self.get("api/v1/health")?;
        Ok(ApiResponse::Health)
    }

    fn publishers(
        &self,
        command: PublishersCommand,
    ) -> Result<ApiResponse, Error> {
        match command {
            PublishersCommand::List => {
                let res = self.get("api/v1/publishers")?;
                let list: PublisherList = serde_json::from_str(&res)?;
                Ok(ApiResponse::PublisherList(list))
            },
            PublishersCommand::Add(path) => {
                let xml_bytes = file::read(&path)?;
                match self.post("api/v1/publishers", xml_bytes)? {
                    Some(body) => {
                        if body.is_empty() {
                            Ok(ApiResponse::Empty)
                        } else {
                            Ok(ApiResponse::GenericBody(body))
                        }
                    },
                    None => Ok(ApiResponse::Empty)
                }
            },
            PublishersCommand::Details(handle) => {
                let uri = format!("api/v1/publishers/{}", handle);
                let res = self.get(uri.as_str())?;
                let details: PublisherDetails = serde_json::from_str(&res)?;
                Ok(ApiResponse::PublisherDetails(details))
            },
            PublishersCommand::RepositoryResponseXml(handle, file_opt) => {
                let uri = format!("api/v1/publishers/{}/response.xml", handle);
                let xml = self.get(uri.as_str())?;
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
                let uri = format!("api/v1/publishers/{}/id.cer", handle);
                let bytes = self.get_binary(uri.as_str())?;
                file::save(&bytes, &file)?;
                Ok(ApiResponse::Empty)
            }
        }
    }

    fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str("krillc").unwrap()
        );
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", &self.token)).unwrap()
        );
        headers
    }

    fn post(&self, rel: &str, bytes: Bytes) -> Result<Option<String>, Error> {
        let headers = self.headers();

        let client = Client::builder()
            .gzip(true)
            .timeout(Duration::from_secs(30))
            .build()?;

        let uri = format!("{}{}", &self.server.to_string(), rel);
        let mut res = client.post(&uri)
            .headers(headers)
            .body(bytes.to_vec())
            .send()?;

        match res.status() {
            StatusCode::OK => {
                Ok(res.text().ok())
            },
            status => {
                match res.text() {
                    Ok(body) => {
                        if body.is_empty() {
                            Err(Error::BadStatus(status))
                        } else {
                            Err(Error::ErrorWithBody(body))
                        }
                    },
                    _ => Err(Error::BadStatus(status))
                }
            }
        }
    }

    /// Sends a get request to the server, including the token for
    /// authorization.
    /// Note that the server uri ends with a '/', so leave out the '/'
    /// from the start of the rel_path when calling this function.
    fn get(
        &self,
        rel_path: &str
    ) -> Result<String, Error> {
        let mut res = self.get_generic(rel_path)?;
        let txt = res.text()?;
        Ok(txt)
    }

    /// Sends a get request to the server, including the token for
    /// authorization.
    /// Note that the server uri ends with a '/', so leave out the '/'
    /// from the start of the rel_path when calling this function.
    fn get_binary(
        &self,
        rel_path: &str
    ) -> Result<Bytes, Error> {
        let mut res = self.get_generic(rel_path)?;
        let mut bytes: Vec<u8> = vec![];
        res.copy_to(&mut bytes)?;
        Ok(Bytes::from(bytes))
    }

    fn get_generic(
        &self,
        rel_path: &str
    ) -> Result<Response, Error> {
        let headers = self.headers();

        let client = Client::builder()
            .gzip(true)
            .timeout(Duration::from_secs(30))
            .build()?;

        let uri = format!("{}{}", &self.server.to_string(), rel_path);
        let mut res = client.get(&uri).headers(headers).send()?;

        match res.status() {
            StatusCode::OK => {
                Ok(res)
            },
            status => {
                match res.text() {
                    Ok(body) => {
                        if body.is_empty() {
                            Err(Error::BadStatus(status))
                        } else {
                            Err(Error::ErrorWithBody(body))
                        }
                    },
                    _ => Err(Error::BadStatus(status))
                }
            }
        }
    }

}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display ="No valid command given, see --help")]
    MissingCommand,

    #[fail(display ="Server is not available.")]
    ServerDown,

    #[fail(display="Request Error: {}", _0)]
    RequestError(reqwest::Error),

    #[fail(display="Received bad status: {}", _0)]
    BadStatus(StatusCode),

    #[fail(display="{}", _0)]
    ErrorWithBody(String),

    #[fail(display="Received invalid json response: {}", _0)]
    JsonError(serde_json::Error),

    #[fail(display="{}", _0)]
    ReportError(ReportError),

    #[fail(display="Can't read file: {}", _0)]
    IoError(io::Error),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::RequestError(e)
    }
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


// Note: this is all tested through integration tests ('tests' folder).