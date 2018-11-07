extern crate hyper;
extern crate futures;

use std::net::SocketAddr;
use self::hyper::{Body, Method, Response, Server, StatusCode};
use self::hyper::rt::Future;
use self::hyper::service::service_fn_ok;
use provisioning::publisher_list::PublisherList;
use serde_json;
use provisioning::publisher_list;

const CSS: &'static [u8]      = include_bytes!("../static/css/custom.css");
const IMG_404: &'static [u8]  = include_bytes!("../static/images/404.png");
const HTML_404: &'static [u8] = include_bytes!("../static/html/404.html");
const PERFECT: &'static str   = "I am completely operational, and all my circuits are functioning perfectly.";

fn render(body: RenderResult) -> Response<Body> {
    let mut res = Response::new(Body::empty());
    match body {
        Ok(body) => { *res.body_mut() = body },
        Err(e) => {
            *res.body_mut() = Body::from(format!("{:?}", e));
            *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        }
    }
    res
}

fn service_ok() -> RenderResult {
    Ok(Body::from(PERFECT))
}

fn read_static_file(path: &str) -> RenderResult {
    match path {
        "/static/css/custom.css" => { Ok(Body::from(CSS)) },
        "/static/images/404.png" => { Ok(Body::from(IMG_404)) },
        "/static/html/404.html"  => { Ok(Body::from(HTML_404)) },
        // Note that the following does not return a 404 to avoid a loop in
        // case the 404 page references an unknown resource. This should be
        // unreachable under normal operation, since we do not get these files
        // based on user input, but only from static &str defined here.
        _                        => { Err(Error::UnknownResource) },
    }
}

fn page_not_found() -> Response<Body> {
    let mut res = render(read_static_file("/static/html/404.html"));
    *res.status_mut() = StatusCode::NOT_FOUND;
    res
}

fn show_publishers(pl: &PublisherList) -> RenderResult {
    let publishers = pl.publishers()?;
    let encoded = serde_json::to_string(&publishers)?;
    Ok(Body::from(encoded))
}



pub fn serve(
    addr: &SocketAddr,
    publisher_list: PublisherList) {

    let new_service = move || {

        let publisher_list = publisher_list.clone();

        service_fn_ok(move |req| {
            let path = req.uri().path();

            if path.starts_with("/static") {
                render(read_static_file(path))
            } else {
                match (req.method(), path) {
                    (&Method::GET, "/health") => {
                        render(service_ok())
                    },
                    (&Method::GET, "/publishers") => {
                        render(show_publishers(&publisher_list))
                    },
                    _ => {
                        page_not_found()
                    },
                }
            }
        })

    };

    let server = Server::bind(addr)
        .serve(new_service)
        .map_err(|e| eprintln!("server error: {}", e));

    hyper::rt::run(server)
}

type RenderResult = Result<Body, Error>;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display ="{}", _0)]
    PublisherListError(publisher_list::Error),

    #[fail(display ="{}", _0)]
    JsonError(serde_json::Error),

    #[fail(display ="Unknown resource")]
    UnknownResource,
}

impl From<publisher_list::Error> for Error {
    fn from(e: publisher_list::Error) -> Self {
        Error::PublisherListError(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::JsonError(e)
    }
}