extern crate rpki_publication_server;

extern crate hyper;
extern crate futures;

use futures::future;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper::rt::Future;
use hyper::service::service_fn;

type BoxFut = Box<Future<Item=Response<Body>, Error=hyper::Error> + Send>;

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

fn request_mapper(req: Request<Body>) -> BoxFut {

    let mut res = Response::new(Body::empty());
    let path = req.uri().path();

    if path.starts_with("/static") {
        *res.body_mut() = read_static_file(path)
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

    Box::new(future::ok(res))

}

fn main() {
    let addr = ([127, 0, 0, 1], 3000).into();

    let server = Server::bind(&addr)
        .serve(|| service_fn(request_mapper))
        .map_err(|e| eprintln!("server error: {}", e));

    // Run this server for... forever!
    hyper::rt::run(server);
}
