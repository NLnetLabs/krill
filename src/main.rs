extern crate rpki_publication_server;

extern crate hyper;
extern crate futures;

use futures::future;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper::rt::Future;
use hyper::service::service_fn;

type BoxFut = Box<Future<Item=Response<Body>, Error=hyper::Error> + Send>;

fn service_ok() -> Body {
    Body::from("I am completely operational, and all my circuits are functioning perfectly.")
}

fn request_mapper(req: Request<Body>) -> BoxFut {

    let mut response = Response::new(Body::empty());

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/health") => {
            *response.body_mut() = { service_ok() }
        },
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
            *response.body_mut() = Body::from("404 - These are not the droids you're looking for.")
        },
    };

    Box::new(future::ok(response))

}

fn main() {
    let addr = ([127, 0, 0, 1], 3000).into();

    let server = Server::bind(&addr)
        .serve(|| service_fn(request_mapper))
        .map_err(|e| eprintln!("server error: {}", e));

    // Run this server for... forever!
    hyper::rt::run(server);
}
