extern crate hyper;
extern crate futures;

use self::hyper::{Body, Method, Response, Server, StatusCode};
use self::hyper::Request;
use self::hyper::rt::Future;
use self::hyper::service::service_fn_ok;
use pubd::config::Config;
use pubd::server;
use pubd::server::PubServer;
use serde_json;
use serde::Serialize;

const CSS: &'static [u8]      = include_bytes!("../../static/css/custom.css");
const IMG_404: &'static [u8]  = include_bytes!("../../static/images/404.png");
const HTML_404: &'static [u8] = include_bytes!("../../static/html/404.html");

pub fn serve(config: &Config) {

    let pub_server = match PubServer::new(
        config.data_dir(),
        config.pub_xml_dir(),
        config.rsync_base(),
        config.service_uri(),
        config.notify_sia()
    ) {
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        },
        Ok(server) => server
    };

    let new_service = move || {

        let pub_server = pub_server.clone();

        service_fn_ok(move |req: Request<Body>| {
            let (parts, _body) = req.into_parts();
            let path = parts.uri.path();

            if path.starts_with("/rfc8181/") {
                let _handle = path.trim_left_matches("/publishers/");
                unimplemented!()
            } else if path.starts_with("/static") {
                render_static(path)
            } else if path.starts_with("/publishers/") {
                let handle = path.trim_left_matches("/publishers/");
                show_repository_response(handle, &pub_server)
            } else {
                match (parts.method, path) {
                    (Method::GET, "/health") => {
                        service_ok()
                    },
                    (Method::GET, "/publishers") => {
                        show_publishers(&pub_server)
                    },
                    _ => {
                        page_not_found()
                    },
                }
            }
        })

    };

    let server = Server::bind(&config.socket_addr())
        .serve(new_service)
        .map_err(|e| eprintln!("server error: {}", e));

    hyper::rt::spawn(server);
}


fn service_ok() -> Response<Body> {
    render_json("I am completely operational, and all my circuits are functioning perfectly.")
}

fn render_static(path: &str) -> Response<Body> {
    let mut res = Response::new(Body::empty());
    match path {
        "/static/css/custom.css" => { *res.body_mut() = Body::from(CSS)},
        "/static/images/404.png" => { *res.body_mut() = Body::from(IMG_404)},
        "/static/html/404.html"  => { *res.body_mut() = Body::from(HTML_404)},
        // Note that the following does not return a 404 to avoid a loop in
        // case the 404 page references an unknown resource. This should be
        // unreachable under normal operation, since we do not get these files
        // based on user input, but only from static &str defined here.
        _ => return render_error(Error::UnknownResource)
    }
    res
}

fn render_json<O: Serialize>(object: O) -> Response<Body> {
    match serde_json::to_string(&object) {
        Ok(encoded) => {
            let mut res = Response::new(Body::empty());
            *res.body_mut() = Body::from(encoded);
            res
        },
        Err(e) => {
            render_error(Error::JsonError(e))
        }
    }
}

fn render_error(error: Error) -> Response<Body> {
    let mut res = Response::new(Body::from(
        format!("I'm afraid I can't do that: {}", error)));
    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    res
}


fn page_not_found() -> Response<Body> {
    let mut res = render_static("/static/html/404.html");
    *res.status_mut() = StatusCode::NOT_FOUND;
    res
}

fn show_publishers(pub_server: &PubServer) -> Response<Body> {
    match pub_server.publishers() {
        Ok(publishers) => render_json(publishers),
        Err(e)         => render_error(Error::ServerError(e))
    }
}

fn show_repository_response(
    publisher_name: &str,
    pub_server: &PubServer
) -> Response<Body> {
    match pub_server.repository_response(publisher_name) {
        Ok(response) => Response::new(Body::from(response.encode_vec())),
        Err(e)       => render_error(Error::ServerError(e))
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display ="{}", _0)]
    ServerError(server::Error),

    #[fail(display ="{}", _0)]
    JsonError(serde_json::Error),

    #[fail(display ="Unknown resource")]
    UnknownResource,
}
