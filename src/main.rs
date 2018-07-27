extern crate rpki_publication_server;

extern crate hyper;
extern crate futures;

use std::fs;

use futures::future;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper::rt::Future;
use hyper::service::service_fn;

type BoxFut = Box<Future<Item=Response<Body>, Error=hyper::Error> + Send>;

fn service_ok() -> Body {
    Body::from("I am completely operational, and all my circuits are functioning perfectly.")
}

fn read_static_file(path: &str) -> Body {
    match path {
        "/static/css/custom.css" => {
            Body::from(fs::read("static/css/custom.css").unwrap()) },
        "/static/images/404.png" => {
            Body::from(fs::read("static/images/404.png").unwrap()) },
        "/static/html/404.html" => {
            Body::from(fs::read("static/html/404.html").unwrap()) },
        _ => { Body::from("Unknown resource") },
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
