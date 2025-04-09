//! `/testbed`
//!
//! Testbed mode enables Krill to run as an open root of a test RPKI hierarchy
//! with web-UI based self-service ability for other RPKI certificate
//! authorities to integrate themselves into the test RPKI hierarchy, both as
//! children whose resources are delegated from the testbed and as publishers
//! into the testbed repository. This feature is very similar to existing
//! web-UI based self-service RPKI test hierarchies such as the RIPE NCC RPKI
//! Test Environment and the APNIC RPKI Testbed.
//!
//! Krill can already do this via a combination of use_ta=true and the
//! existing Krill API _but_ crucially the other RPKI certificate authorities
//! would need to know the Krill API token in order to register themselves
//! with the Krill testbed, giving them far too much power over the testbed.
//! Testbed mode exposes *open* `/testbed/xxx` wrapper API endpoints for
//! exchanging the RFC 8183 XMLs, e.g.:
//!
//! * `/testbed/enabled`: should the web-UI show the testbed UI page?
//! * `/testbed/children`: `<client_request/>` in, `<parent_response/>` out
//! * `/testbed/publishers`: `<publisher_request/>` in,
//!   `<repository_response/>` out
//!
//! This feature assumes the existence of a built-in "testbed" CA and
//! publisher when testbed mode is enabled.

use rpki::ca::idexchange::{ChildHandle, PublisherHandle};
use crate::commons::actor::Actor;
use crate::constants::testbed_ca_handle;
use super::super::request::{Request, PathIter};
use super::super::response::HttpResponse;
use super::error::DispatchError;


//------------ /testbed ------------------------------------------------------

pub async fn dispatch(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    if !request.testbed_enabled() {
        return Ok(HttpResponse::not_found())
    }

    match path.next() {
        Some("enabled") => enabled(request, path),
        Some("children") => children(request, path).await,
        Some("publishers") => publishers(request, path).await,
        _ => Ok(HttpResponse::not_found())
    }
}


//------------ /testbed/enabled ----------------------------------------------

fn enabled(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_unchecked();
    let _server = request.empty()?;
    Ok(HttpResponse::ok())
}


//------------ /testbed/children ---------------------------------------------

async fn children(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.parse_opt_next()? {
        None => children_index(request).await,
        Some(child) => children_child(request, path, child),
    }
}

async fn children_index(
    request: Request<'_>
) -> Result<HttpResponse, DispatchError> {
    request.check_post()?;
    let (request, _) = request.proceed_unchecked();
    let (server, child) = request.json().await?;
    Ok(HttpResponse::json(
        &server.krill().ca_add_child(
            &testbed_ca_handle(), child, &Actor::anonymous()
        )?
    ))
}

fn children_child(
    request: Request<'_>,
    mut path: PathIter<'_>,
    child: ChildHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        None => children_child_index(request, child),
        Some("parent_response.xml") => {
            children_child_response(request, path, child)
        }
        _ => Ok(HttpResponse::not_found())
    }
}

fn children_child_index(
    request: Request<'_>,
    child: ChildHandle,
) -> Result<HttpResponse, DispatchError> {
    request.check_delete()?;
    let (request, _) = request.proceed_unchecked();
    let server = request.empty()?;
    server.krill().ca_child_remove(
        &testbed_ca_handle(), child, &Actor::anonymous()
    )?;
    Ok(HttpResponse::ok())
}

fn children_child_response(
    request: Request<'_>,
    path: PathIter<'_>,
    child: ChildHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_unchecked();
    let server = request.empty()?;
    Ok(HttpResponse::xml(
        server.krill().ca_parent_response(
            &testbed_ca_handle(), child
        )?.to_xml_vec()
    ))
}


//------------ /testbed/publishers -------------------------------------------

async fn publishers(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.parse_opt_next()? {
        None => publishers_index(request).await,
        Some(publisher) => publishers_publisher(request, path, publisher),
    }
}

async fn publishers_index(
    request: Request<'_>
) -> Result<HttpResponse, DispatchError> {
    request.check_post()?;
    let (request, _) = request.proceed_unchecked();
    let (server, pbl) = request.json().await?;
    server.krill().add_publisher(pbl, &Actor::anonymous())?;
    Ok(HttpResponse::ok())
}

fn publishers_publisher(
    request: Request<'_>,
    mut path: PathIter<'_>,
    publisher: PublisherHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        None => publishers_publisher_index(request, publisher),
        Some("response.xml") => {
            publishers_publisher_response(request, path, publisher)
        }
        _ => Ok(HttpResponse::not_found())
    }
}

fn publishers_publisher_index(
    request: Request<'_>,
    publisher: PublisherHandle,
) -> Result<HttpResponse, DispatchError> {
    request.check_delete()?;
    let (request, _) = request.proceed_unchecked();
    let server = request.empty()?;
    server.krill().remove_publisher(
        publisher, &Actor::anonymous()
    )?;
    Ok(HttpResponse::ok())
}

fn publishers_publisher_response(
    request: Request<'_>,
    path: PathIter<'_>,
    publisher: PublisherHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_unchecked();
    let server = request.empty()?;
    Ok(HttpResponse::xml(
        server.krill().repository_response(&publisher)?.to_xml_vec()
    ))
}

