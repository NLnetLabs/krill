//! `/api/v1/pubd`

use hyper::Method;
use rpki::ca::idexchange::PublisherHandle;
use crate::api::admin::{PublisherList, PublisherSummary};
use super::super::auth::Permission;
use super::super::request::{PathIter, Request};
use super::super::response::HttpResponse;
use super::error::DispatchError;

//------------ /api/v1/pubd --------------------------------------------------

pub async fn dispatch(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    request.check_permission(Permission::PubAdmin, None)?;

    match path.next() {
        Some("delete") => delete(request, path).await,
        Some("init") => init(request, path).await,
        Some("publishers") => publishers(request, path).await,
        Some("session_reset") => session_reset(request, path),
        Some("stale") => stale(request, path).await,
        _ => Ok(HttpResponse::not_found())
    }
}


//------------ /api/v1/pubd/delete -------------------------------------------

async fn delete(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, _) = request.proceed_permitted(
        Permission::PubAdmin, None
    )?;
    let (server, criteria) = request.json().await?;
    server.krill().delete_matching_files(criteria)?;
    Ok(HttpResponse::ok())
}


//------------ /api/v1/pubd/init ---------------------------------------------

async fn init(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    match *request.method() {
        Method::POST => {
            let (request, _) = request.proceed_permitted(
                Permission::PubAdmin, None
            )?;
            let (server, uris) = request.json().await?;
            server.krill().repository_init(uris)?;
            Ok(HttpResponse::ok())
        }
        Method::DELETE => {
            let (request, _) = request.proceed_permitted(
                Permission::PubAdmin, None
            )?;
            let server = request.empty()?;
            server.krill().repository_clear()?;
            Ok(HttpResponse::ok())
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}


//------------ /api/v1/pubd/publishers ---------------------------------------

async fn publishers(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.parse_opt_next()? {
        None => publishers_index(request).await,
        Some(publisher) => {
            publishers_publisher(request, path, publisher)
        }
    }
}

async fn publishers_index(
    request: Request<'_>,
) -> Result<HttpResponse, DispatchError> {
    match *request.method() {
        Method::GET => {
            let (request, _) = request.proceed_permitted(
                Permission::PubList, None
            )?;
            let server = request.empty()?;
            Ok(HttpResponse::json(
                &PublisherList {
                    publishers: {
                        server.krill().publishers()?.into_iter().map(
                            PublisherSummary::from_handle
                        ).collect()
                    }
                }
            ))
        }
        Method::POST => {
            let (request, auth) = request.proceed_permitted(
                Permission::PubCreate, None
            )?;
            let (server, pbl) = request.json().await?;
            server.krill().add_publisher(pbl, auth.actor())?;
            Ok(HttpResponse::ok())
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

fn publishers_publisher(
    request: Request<'_>,
    mut path: PathIter<'_>,
    publisher: PublisherHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        None => publishers_publisher_index(request, publisher),
        Some("response.json") => {
            publishers_publisher_response(request, path, publisher)
        }
        Some("response.xml") => {
            publishers_publisher_response_xml(request, path, publisher)
        }
        _ => Ok(HttpResponse::not_found())
    }
}

fn publishers_publisher_index(
    request: Request<'_>,
    publisher: PublisherHandle,
) -> Result<HttpResponse, DispatchError> {
    match *request.method() {
        Method::GET => {
            let (request, _) = request.proceed_permitted(
                Permission::PubRead, None
            )?;
            let server = request.empty()?;
            Ok(HttpResponse::json(
                &server.krill().get_publisher(publisher)?
            ))
        }
        Method::DELETE => {
            let (request, auth) = request.proceed_permitted(
                Permission::PubDelete, None
            )?;
            let server = request.empty()?;
            server.krill().remove_publisher(publisher, auth.actor())?;
            Ok(HttpResponse::ok())
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

fn publishers_publisher_response(
    request: Request<'_>,
    path: PathIter<'_>,
    publisher: PublisherHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(Permission::PubRead, None)?;
    let server = request.empty()?;
    Ok(HttpResponse::json(
        &server.krill().repository_response(&publisher)?
    ))
}

fn publishers_publisher_response_xml(
    request: Request<'_>,
    path: PathIter<'_>,
    publisher: PublisherHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(Permission::PubRead, None)?;
    let server = request.empty()?;
    Ok(HttpResponse::xml(
        server.krill().repository_response(&publisher)?.to_xml_vec()
    ))
}


//------------ /api/v1/pubd/session_reset ------------------------------------

fn session_reset(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, _) = request.proceed_permitted(Permission::PubAdmin, None)?;
    let server = request.empty()?;
    server.krill().repository_session_reset()?;
    Ok(HttpResponse::ok())
}


//------------ /api/v1/pubd/stale --------------------------------------------

async fn stale(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    let seconds = path.parse_opt_next()?.unwrap_or(0);
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted( Permission::PubList, None)?;
    let server = request.empty()?;
    let stats = server.krill().repo_stats()?;
    Ok(HttpResponse::json(
        &PublisherList {
            publishers: {
                stats.stale_publishers(seconds).map(
                    PublisherSummary::from_handle
                ).collect()
            }
        }
    ))
}

