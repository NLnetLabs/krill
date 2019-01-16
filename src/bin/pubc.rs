//! Command line client to the publication server.
//!
//! Can be used for testing the publication server, but may also be useful
//! for setups where a CA simply writes its current state to some disk, so
//! that this CLI may be triggered to synchronise this state to a publication
//! server.

#[macro_use] extern crate derive_more;
extern crate krill;
extern crate rpki;

use std::io::{self, Write};
use std::path::PathBuf;
use krill::client::pubc::{self, Config, RunMode, PubClient };
use krill::remote::oob::{RepositoryResponse, RepositoryResponseError};
use krill::util::file;

fn main() {

    let config = match Config::create() {
        Ok(c)  => c,
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    };

    let client = match PubClient::new(config.state_dir()) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    };

    let result = match config.mode() {
        RunMode::Init(name)             => init(client, name),
        RunMode::PublisherRequest(path) => publisher_request(client, path),
        RunMode::RepoResponse(path)     => process_response(client, path),
        RunMode::Sync(path)             => sync(client, path),
        RunMode::Unset                  => Err(Error::MissingSubcommand)
    };
    match result {
        Ok(()) => {}//,
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    }
}

fn init(mut client: PubClient, name: &str) -> Result<(), Error> {
    client.init(name)?;
    Ok(())
}

fn publisher_request(
    mut client: PubClient,
    path: &PathBuf
) -> Result<(), Error> {
    let req = client.publisher_request()?;
    let mut file = file::create_file_with_path(&path)?;
    file.write(&req.encode_vec())?;
    Ok(())
}

fn process_response(
    mut client: PubClient,
    path: &PathBuf
) -> Result<(), Error> {
    let bytes = file::read(path)?;
    let res = RepositoryResponse::decode(bytes.as_ref())?;
    res.validate()?;
    client.process_repo_response(res)?;
    Ok(())
}

fn sync(mut client: PubClient, path: &PathBuf) -> Result<(), Error> {
    client.sync_dir(path)?;
    Ok(())
}

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt="{}", _0)]
    ClientError(pubc::Error),

    #[display(fmt="{}", _0)]
    IoError(io::Error),

    #[display(fmt="{}", _0)]
    RepositoryResponseError(RepositoryResponseError),

    #[display(fmt="No sub-command given, see --help")]
    MissingSubcommand,

}

impl From<pubc::Error> for Error {
    fn from(e: pubc::Error) -> Self {
        Error::ClientError(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<RepositoryResponseError> for Error {
    fn from(e: RepositoryResponseError) -> Self {
        Error::RepositoryResponseError(e)
    }
}

