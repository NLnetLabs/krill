extern crate hyper;
extern crate futures;

use std::net::SocketAddr;
use self::hyper::{Body, Method, Response, Server, StatusCode};
use self::hyper::rt::Future;
use self::hyper::service::service_fn_ok;
use std::sync::Arc;
use provisioning::publisher_list::PublisherList;

const CSS: &'static [u8]      = include_bytes!("../static/css/custom.css");
const IMG_404: &'static [u8]  = include_bytes!("../static/images/404.png");
const HTML_404: &'static [u8] = include_bytes!("../static/html/404.html");
const UNKNOWN: &'static str   = "Unknown resource";
const PERFECT: &'static str   = "I am completely operational, and all my circuits are functioning perfectly.";

fn service_ok() -> Body {
    Body::from(PERFECT)
}

fn read_static_file(path: &str) -> Body {
    match path {
        "/static/css/custom.css" => { Body::from(CSS) },
        "/static/images/404.png" => { Body::from(IMG_404) },
        "/static/html/404.html"  => { Body::from(HTML_404) },
        _                        => { Body::from(UNKNOWN) },
    }
}

fn show_publishers(pl: Arc<PublisherList>) -> Body {
    Body::from(format!("Configured {} publishers." , pl.publishers().unwrap
    ().len()))
}



pub fn serve(
    addr: &SocketAddr,
    publisher_list: Arc<PublisherList>) {

    let new_service = move || {

        let publisher_list = publisher_list.clone();

        service_fn_ok(move |req| {
            let mut res = Response::new(Body::empty());
            let path = req.uri().path();

            if path.starts_with("/static") {
                *res.body_mut() = read_static_file(path)
            } else if path == "/publishers/" {
                *res.body_mut() = { show_publishers(publisher_list.clone()) }
            } else {
                match (req.method(), path) {
                    (&Method::GET, "/health") => {
                        *res.body_mut() = { service_ok() }
                    },
                    _ => {
                        *res.status_mut() = StatusCode::NOT_FOUND;
                        *res.body_mut() = read_static_file("/static/html/404.html")
                    },
                };
            }
            res
        })

    };

    let server = Server::bind(addr)
        .serve(new_service)
        .map_err(|e| eprintln!("server error: {}", e));

    hyper::rt::run(server)
}