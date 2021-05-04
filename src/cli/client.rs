use std::{env, fmt};

use serde::de::DeserializeOwned;
use serde::Serialize;

use rpki::uri;

#[cfg(feature = "multi-user")]
use crate::cli::options::KrillUserDetails;
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
use crate::{
    cli::options::{BulkCaCommand, CaCommand, Command, KrillInitDetails, KrillPubcOptions, Options, PublishersCommand},
    commons::error::KrillIoError,
};

#[cfg(feature = "multi-user")]
use crate::constants::{PW_HASH_LOG_N, PW_HASH_P, PW_HASH_R};

fn resolve_uri(server: &uri::Https, path: &str) -> String {
    format!("{}{}", server, path)
}

async fn get_json<T: DeserializeOwned>(server: &uri::Https, token: &Token, path: &str) -> Result<T, Error> {
    let uri = resolve_uri(server, path);
    httpclient::get_json(&uri, Some(token))
        .await
        .map_err(Error::HttpClientError)
}

async fn post_empty(server: &uri::Https, token: &Token, path: &str) -> Result<(), Error> {
    let uri = resolve_uri(server, path);
    httpclient::post_empty(&uri, Some(token))
        .await
        .map_err(Error::HttpClientError)
}

async fn post_json(server: &uri::Https, token: &Token, path: &str, data: impl Serialize) -> Result<(), Error> {
    let uri = resolve_uri(server, path);
    httpclient::post_json(&uri, data, Some(token))
        .await
        .map_err(Error::HttpClientError)
}

async fn post_json_with_response<T: DeserializeOwned>(
    server: &uri::Https,
    token: &Token,
    path: &str,
    data: impl Serialize,
) -> Result<T, Error> {
    let uri = resolve_uri(server, path);
    httpclient::post_json_with_response(&uri, data, Some(token))
        .await
        .map_err(Error::HttpClientError)
}

async fn post_json_with_opt_response<T: DeserializeOwned>(
    server: &uri::Https,
    token: &Token,
    uri: &str,
    data: impl Serialize,
) -> Result<Option<T>, Error> {
    let uri = resolve_uri(server, uri);
    httpclient::post_json_with_opt_response(&uri, data, Some(token))
        .await
        .map_err(Error::HttpClientError)
}

async fn delete(server: &uri::Https, token: &Token, uri: &str) -> Result<(), Error> {
    let uri = resolve_uri(server, uri);
    httpclient::delete(&uri, Some(token))
        .await
        .map_err(Error::HttpClientError)
}

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
            Command::Init(details) => client.init_config(details),
            #[cfg(feature = "multi-user")]
            Command::User(cmd) => client.user(cmd),
            Command::NotSet => Err(Error::MissingCommand),
        }
    }

    async fn health(&self) -> Result<ApiResponse, Error> {
        httpclient::get_ok(&resolve_uri(&self.server, "api/v1/authorized"), Some(&self.token)).await?;
        Ok(ApiResponse::Health)
    }

    async fn info(&self) -> Result<ApiResponse, Error> {
        let info = httpclient::get_json(&resolve_uri(&self.server, "stats/info"), Some(&self.token)).await?;
        Ok(ApiResponse::Info(info))
    }

    async fn bulk(&self, command: BulkCaCommand) -> Result<ApiResponse, Error> {
        match command {
            BulkCaCommand::Refresh => {
                post_empty(&self.server, &self.token, "api/v1/bulk/cas/sync/parent").await?;
                Ok(ApiResponse::Empty)
            }
            BulkCaCommand::Publish => {
                post_empty(&self.server, &self.token, "api/v1/bulk/cas/publish").await?;
                Ok(ApiResponse::Empty)
            }
            BulkCaCommand::Sync => {
                post_empty(&self.server, &self.token, "api/v1/bulk/cas/sync/repo").await?;
                Ok(ApiResponse::Empty)
            }
        }
    }

    #[allow(clippy::cognitive_complexity)]
    async fn certauth(&self, command: CaCommand) -> Result<ApiResponse, Error> {
        match command {
            CaCommand::Init(init) => {
                post_json(&self.server, &self.token, "api/v1/cas", init).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::Delete(ca) => {
                let uri = format!("api/v1/cas/{}", ca);
                delete(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::UpdateId(handle) => {
                let uri = format!("api/v1/cas/{}/id", handle);
                post_empty(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::ParentResponse(handle, child) => {
                let uri = format!("api/v1/cas/{}/children/{}/contact", handle, child);
                let info: ParentCaContact = get_json(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::ParentCaContact(info))
            }

            CaCommand::ChildRequest(handle) => {
                let uri = format!("api/v1/cas/{}/id/child_request.json", handle);
                let req = get_json(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::Rfc8183ChildRequest(req))
            }

            CaCommand::RepoPublisherRequest(handle) => {
                let uri = format!("api/v1/cas/{}/id/publisher_request.json", handle);
                let req: rfc8183::PublisherRequest = get_json(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::Rfc8183PublisherRequest(req))
            }

            CaCommand::RepoDetails(handle) => {
                let uri = format!("api/v1/cas/{}/repo", handle);
                let details: CaRepoDetails = get_json(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::RepoDetails(details))
            }

            CaCommand::RepoStatus(ca) => {
                let uri = format!("api/v1/cas/{}/repo/status", ca);
                let status: RepoStatus = get_json(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::RepoStatus(status))
            }

            CaCommand::RepoUpdate(handle, update) => {
                let uri = format!("api/v1/cas/{}/repo", handle);
                post_json(&self.server, &self.token, &uri, update).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::AddParent(handle, parent_req) => {
                let uri = format!("api/v1/cas/{}/parents", handle);
                post_json(&self.server, &self.token, &uri, parent_req).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::RemoveParent(handle, parent) => {
                let uri = format!("api/v1/cas/{}/parents/{}", handle, parent);
                delete(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::ParentStatuses(handle) => {
                let uri = format!("api/v1/cas/{}/parents", handle);
                let statuses: ParentStatuses = get_json(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::ParentStatuses(statuses))
            }

            CaCommand::MyParentCaContact(handle, parent) => {
                let uri = format!("api/v1/cas/{}/parents/{}", handle, parent);
                let parent: ParentCaContact = get_json(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::ParentCaContact(parent))
            }

            CaCommand::ChildInfo(handle, child) => {
                let uri = format!("api/v1/cas/{}/children/{}", handle, child);
                let info: ChildCaInfo = get_json(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::ChildInfo(info))
            }

            CaCommand::ChildAdd(handle, req) => {
                let uri = format!("api/v1/cas/{}/children", handle);
                let info: ParentCaContact = post_json_with_response(&self.server, &self.token, &uri, req).await?;
                Ok(ApiResponse::ParentCaContact(info))
            }
            CaCommand::ChildUpdate(handle, child, req) => {
                let uri = format!("api/v1/cas/{}/children/{}", handle, child);
                post_json(&self.server, &self.token, &uri, req).await?;
                Ok(ApiResponse::Empty)
            }
            CaCommand::ChildDelete(handle, child) => {
                let uri = format!("api/v1/cas/{}/children/{}", handle, child);
                delete(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::KeyRollInit(handle) => {
                let uri = format!("api/v1/cas/{}/keys/roll_init", handle);
                post_empty(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::Empty)
            }
            CaCommand::KeyRollActivate(handle) => {
                let uri = format!("api/v1/cas/{}/keys/roll_activate", handle);
                post_empty(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::RouteAuthorizationsList(handle) => {
                let uri = format!("api/v1/cas/{}/routes", handle);
                let roas = get_json(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::RouteAuthorizations(roas))
            }

            CaCommand::RouteAuthorizationsUpdate(handle, updates) => {
                let uri = format!("api/v1/cas/{}/routes", handle);
                post_json(&self.server, &self.token, &uri, updates).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::RouteAuthorizationsTryUpdate(handle, updates) => {
                let uri = format!("api/v1/cas/{}/routes/try", handle);
                let advice_opt: Option<BgpAnalysisAdvice> =
                    post_json_with_opt_response(&self.server, &self.token, &uri, updates).await?;
                match advice_opt {
                    None => Ok(ApiResponse::Empty),
                    Some(advice) => Ok(ApiResponse::BgpAnalysisAdvice(advice)),
                }
            }

            CaCommand::RouteAuthorizationsDryRunUpdate(handle, updates) => {
                let uri = format!("api/v1/cas/{}/routes/analysis/dryrun", handle);
                let report = post_json_with_response(&self.server, &self.token, &uri, updates).await?;
                Ok(ApiResponse::BgpAnalysisFull(report))
            }

            CaCommand::BgpAnalysisFull(handle) => {
                let uri = format!("api/v1/cas/{}/routes/analysis/full", handle);
                let report = get_json(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::BgpAnalysisFull(report))
            }

            CaCommand::BgpAnalysisSuggest(handle, resources) => {
                let uri = format!("api/v1/cas/{}/routes/analysis/suggest", handle);

                let suggestions = if let Some(resources) = resources {
                    post_json_with_response(&self.server, &self.token, &uri, resources).await?
                } else {
                    get_json(&self.server, &self.token, &uri).await?
                };

                Ok(ApiResponse::BgpAnalysisSuggestions(suggestions))
            }

            CaCommand::Show(handle) => {
                let uri = format!("api/v1/cas/{}", handle);
                let ca_info = get_json(&self.server, &self.token, &uri).await?;

                Ok(ApiResponse::CertAuthInfo(ca_info))
            }

            CaCommand::ShowHistoryCommands(handle, options) => {
                let uri = format!(
                    "api/v1/cas/{}/history/commands/{}",
                    handle,
                    options.url_path_parameters()
                );
                let history = get_json(&self.server, &self.token, &uri).await?;

                Ok(ApiResponse::CertAuthHistory(history))
            }

            CaCommand::ShowHistoryDetails(handle, key) => {
                let uri = format!("api/v1/cas/{}/history/details/{}", handle, key);
                let action = get_json(&self.server, &self.token, &uri).await?;

                Ok(ApiResponse::CertAuthAction(action))
            }

            CaCommand::Issues(ca_opt) => match ca_opt {
                Some(ca) => {
                    let uri = format!("api/v1/cas/{}/issues", ca);
                    let issues: CertAuthIssues = get_json(&self.server, &self.token, &uri).await?;
                    Ok(ApiResponse::CertAuthIssues(issues))
                }
                None => {
                    let issues: AllCertAuthIssues =
                        get_json(&self.server, &self.token, "api/v1/bulk/cas/issues").await?;
                    Ok(ApiResponse::AllCertAuthIssues(issues))
                }
            },

            CaCommand::RtaList(ca) => {
                let uri = format!("api/v1/cas/{}/rta/", ca);
                let list = get_json(&self.server, &self.token, &uri).await?;
                Ok(ApiResponse::RtaList(list))
            }

            CaCommand::RtaShow(ca, name, out) => {
                let uri = format!("api/v1/cas/{}/rta/{}", ca, name);
                let rta = get_json(&self.server, &self.token, &uri).await?;

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
                post_json(&self.server, &self.token, &uri, request).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::RtaMultiPrep(ca, name, resources) => {
                let uri = format!("api/v1/cas/{}/rta/{}/multi/prep", ca, name);
                let response = post_json_with_response(&self.server, &self.token, &uri, resources).await?;
                Ok(ApiResponse::RtaMultiPrep(response))
            }

            CaCommand::RtaMultiCoSign(ca, name, rta) => {
                let uri = format!("api/v1/cas/{}/rta/{}/multi/cosign", ca, name);
                post_json(&self.server, &self.token, &uri, rta).await?;
                Ok(ApiResponse::Empty)
            }

            CaCommand::List => {
                let cas = get_json(&self.server, &self.token, "api/v1/cas").await?;
                Ok(ApiResponse::CertAuths(cas))
            }
        }
    }

    fn init_config(&self, details: KrillInitDetails) -> Result<ApiResponse, Error> {
        let defaults = include_str!("../../defaults/krill.conf");
        let multi_add_on = include_str!("../../defaults/krill-multi-user.conf");

        let mut config = defaults.to_string();
        config = config.replace("### admin_token =", &format!("admin_token = \"{}\"", self.token));

        config = config.replace(
            "### service_uri = \"https://localhost:3000/\"",
            &format!("service_uri = \"{}\"", self.server),
        );

        if let Some(data_dir) = details.data_dir() {
            config = config.replace("### data_dir = \"./data\"", &format!("data_dir = \"{}\"", data_dir))
        }

        if let Some(log_file) = details.log_file() {
            config = config.replace(
                "### log_file = \"./krill.log\"",
                &format!("log_file = \"{}\"", log_file),
            )
        }

        if details.multi_user() {
            config.push_str("\n\n\n");
            config.push_str(multi_add_on);
        }

        let c: Config = toml::from_slice(config.as_ref()).map_err(Error::init)?;
        c.verify().map_err(Error::init)?;

        Ok(ApiResponse::GenericBody(config))
    }

    #[cfg(feature = "multi-user")]
    #[allow(clippy::clippy::unnecessary_wraps)]
    fn user(&self, details: KrillUserDetails) -> Result<ApiResponse, Error> {
        let (password_hash, salt) = {
            use scrypt::scrypt;

            let password = rpassword::read_password_from_tty(Some("Enter the password to hash: ")).unwrap();

            // The scrypt-js NPM documentation (https://www.npmjs.com/package/scrypt-js) says:
            //   "TL;DR - either only allow ASCII characters in passwords, or use
            //            String.prototype.normalize('NFKC') on any password"
            // So in Lagosta we do the NFKC normalization and thus we need to do the same here.
            use unicode_normalization::UnicodeNormalization;

            let user_id = details.id().nfkc().collect::<String>();
            let password = password.trim().nfkc().collect::<String>();
            let params = scrypt::Params::new(PW_HASH_LOG_N, PW_HASH_R, PW_HASH_P).unwrap();

            // hash twice with two different salts
            // hash first with a salt the client browser knows how to construct based on the users id and a site
            // specific string.

            let weak_salt = format!("krill-lagosta-{}", user_id);
            let weak_salt = weak_salt.nfkc().collect::<String>();

            let mut interim_hash: [u8; 32] = [0; 32];
            scrypt(password.as_bytes(), weak_salt.as_bytes(), &params, &mut interim_hash).unwrap();

            // hash again using a strong random salt only known to the server
            let mut strong_salt: [u8; 32] = [0; 32];
            openssl::rand::rand_bytes(&mut strong_salt).unwrap();
            let mut final_hash: [u8; 32] = [0; 32];
            scrypt(&interim_hash, &strong_salt, &params, &mut final_hash).unwrap();

            (final_hash, strong_salt)
        };

        // Due to https://github.com/alexcrichton/toml-rs/issues/406 we cannot
        // produce inline table style TOML by serializing from config structs to
        // a string using the toml crate. Instead we build it up ourselves.
        let attrs = details.attrs();
        let attrs_fragment = match attrs.is_empty() {
            false => format!(
                "attributes={{ {} }}, ",
                attrs
                    .iter()
                    // quote the key if needed
                    .map(|(k, v)| match k.contains(' ') {
                        true => (format!(r#""{}""#, k), v),
                        false => (k.clone(), v),
                    })
                    // quote the value
                    .map(|(k, v)| format!(r#"{}="{}""#, k, v))
                    .collect::<Vec<String>>()
                    .join(", ")
            ),
            true => String::new(),
        };

        let toml = format!(
            r#"
[auth_users]
"{id}" = {{ {attrs}password_hash="{ph}", salt="{salt}" }}"#,
            id = details.id(),
            attrs = attrs_fragment,
            ph = hex::encode(password_hash),
            salt = hex::encode(salt),
        );

        Ok(ApiResponse::GenericBody(toml))
    }
}

//------------ KrillPubdClient -----------------------------------------------

pub struct KrillPubdClient;

impl KrillPubdClient {
    /// Delegates the options to be processed, and reports the response
    /// back to the user. Note that error reporting is handled by CLI.
    pub async fn report(options: KrillPubcOptions) -> Result<(), Error> {
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
    pub async fn process(options: KrillPubcOptions) -> Result<ApiResponse, Error> {
        let (server, token, _format, api, command) = options.unpack();

        if api {
            // passing the api option in the env, so that the call
            // to the back-end will just print and exit.
            env::set_var(KRILL_CLI_API_ENV, "1")
        }

        match command {
            PublishersCommand::PublisherList => {
                let list: PublisherList = get_json(&server, &token, "api/v1/pubd/publishers").await?;
                Ok(ApiResponse::PublisherList(list))
            }
            PublishersCommand::StalePublishers(seconds) => {
                let uri = format!("api/v1/pubd/stale/{}", seconds);
                let stales = get_json(&server, &token, &uri).await?;
                Ok(ApiResponse::PublisherList(stales))
            }
            PublishersCommand::RepositoryStats => {
                let stats = get_json(&server, &token, "stats/repo").await?;
                Ok(ApiResponse::RepoStats(stats))
            }
            PublishersCommand::RepositoryInit(uris) => {
                let uri = "api/v1/pubd/init";
                post_json(&server, &token, uri, uris).await?;
                Ok(ApiResponse::Empty)
            }
            PublishersCommand::RepositoryClear => {
                let uri = "api/v1/pubd/init";
                delete(&server, &token, uri).await?;
                Ok(ApiResponse::Empty)
            }
            PublishersCommand::AddPublisher(req) => {
                let res = post_json_with_response(&server, &token, "api/v1/pubd/publishers", req).await?;
                Ok(ApiResponse::Rfc8183RepositoryResponse(res))
            }
            PublishersCommand::RemovePublisher(handle) => {
                let uri = format!("api/v1/pubd/publishers/{}", handle);
                delete(&server, &token, &uri).await?;
                Ok(ApiResponse::Empty)
            }
            PublishersCommand::ShowPublisher(handle) => {
                let uri = format!("api/v1/pubd/publishers/{}", handle);
                let details: PublisherDetails = get_json(&server, &token, &uri).await?;
                Ok(ApiResponse::PublisherDetails(details))
            }
            PublishersCommand::RepositoryResponse(handle) => {
                let uri = format!("api/v1/pubd/publishers/{}/response.json", handle);
                let res = get_json(&server, &token, &uri).await?;
                Ok(ApiResponse::Rfc8183RepositoryResponse(res))
            }
        }
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
    IoError(KrillIoError),
    EmptyResponse,
    Rfc8183(rfc8183::Error),
    InitError(String),
    InputError(String),
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
            Error::InputError(s) => s.fmt(f),
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

impl From<KrillIoError> for Error {
    fn from(e: KrillIoError) -> Self {
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
        details.with_data_dir("/var/lib/krill/data/");
        details.with_log_file("/var/log/krill/krill.log");

        let client = KrillClient {
            server: test::https("https://localhost:3001/"),
            token: Token::from("secret"),
        };

        let res = client.init_config(details).unwrap();

        match res {
            ApiResponse::GenericBody(body) => {
                let expected = include_str!("../../test-resources/krill-init.conf");
                assert_eq!(expected, &body)
            }
            _ => panic!("Expected body"),
        }
    }

    #[test]
    fn init_multi_user_config_file() {
        let mut details = KrillInitDetails::multi_user_dflt();
        details.with_data_dir("/var/lib/krill/data/");
        details.with_log_file("/var/log/krill/krill.log");

        let client = KrillClient {
            server: test::https("https://localhost:3001/"),
            token: Token::from("secret"),
        };

        let res = client.init_config(details).unwrap();

        match res {
            ApiResponse::GenericBody(body) => {
                let expected = include_str!("../../test-resources/krill-init-multi-user.conf");
                assert_eq!(expected, &body)
            }
            _ => panic!("Expected body"),
        }
    }
}
