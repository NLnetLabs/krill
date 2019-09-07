extern crate clap;
#[macro_use]
extern crate derive_more;
extern crate rpki;
#[macro_use]
extern crate serde;

extern crate krill_commons;

pub mod apiclient;
pub mod cmsclient;

use std::path::PathBuf;

use rpki::uri;

use krill_commons::api::{ListReply, PublishDelta, PublishDeltaBuilder, Withdraw};
use krill_commons::util::file;

pub fn create_delta(
    list_reply: &ListReply,
    dir: &PathBuf,
    base_rsync: &uri::Rsync,
) -> Result<PublishDelta, file::Error> {
    let mut delta_builder = PublishDeltaBuilder::new();

    let current = file::crawl_incl_rsync_base(dir, base_rsync)?;

    // loop through what the server has and find the ones to withdraw
    for p in list_reply.elements() {
        if current.iter().find(|c| c.uri() == p.uri()).is_none() {
            delta_builder.add_withdraw(Withdraw::from_list_element(p));
        }
    }

    // loop through all current files on disk and find out which ones need
    // to be added to, which need to be updated at, or for which no change is
    // needed at the server.
    for f in current {
        match list_reply
            .elements()
            .iter()
            .find(|pbl| pbl.uri() == f.uri())
        {
            None => delta_builder.add_publish(f.as_publish()),
            Some(pbl) => {
                if pbl.hash() != f.hash() {
                    delta_builder.add_update(f.as_update(pbl.hash()))
                }
            }
        }
    }

    Ok(delta_builder.finish())
}

//------------ Format --------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Format {
    Json,
    Text,
    None,
}

impl Format {
    fn from(s: &str) -> Result<Self, UnsupportedFormat> {
        match s {
            "text" => Ok(Format::Text),
            "none" => Ok(Format::None),
            "json" => Ok(Format::Json),
            _ => Err(UnsupportedFormat),
        }
    }
}

pub struct UnsupportedFormat;

//------------ ApiResponse ---------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApiResponse {
    Success,
    List(ListReply),
}

impl ApiResponse {
    pub fn report(&self, format: &Format) {
        match format {
            Format::None => {} // done,
            Format::Json => {
                match self {
                    ApiResponse::Success => {} // nothing to report
                    ApiResponse::List(reply) => {
                        println!("{}", serde_json::to_string(reply).unwrap());
                    }
                }
            }
            Format::Text => match self {
                ApiResponse::Success => println!("success"),
                ApiResponse::List(list) => {
                    for el in list.elements() {
                        println!("{} {}", el.hash().to_string(), el.uri().to_string());
                    }
                }
            },
        }
    }
}
