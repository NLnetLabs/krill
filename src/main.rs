extern crate rpki_publication_server;

extern crate hyper;

use hyper::{Body, Request, Response, Server};
use hyper::rt::Future;
use hyper::service::service_fn_ok;
use std::net::SocketAddr;

fn service_ok(_req: Request<Body>) -> Response<Body> {
    Response::new(Body::from(
        "I am completely operational, and all my circuits are functioning perfectly."))
}

fn main() {
    let addr: SocketAddr = ([127, 0, 0, 1], 3000).into();

    let health_svc = || {
        // service_fn_ok converts our function into a `Service`
        service_fn_ok(service_ok)
    };

    let server = Server::bind(&addr)
        .serve(health_svc)
        .map_err(|e| eprintln!("server error: {}", e));

    // Run this server for... forever!
    hyper::rt::run(server);
}
