//! `/api/v1/ta`

use hyper::Method;
use rpki::ca::idexchange::ChildHandle;
use crate::commons::error::Error;
use crate::constants::ta_handle;
use super::super::auth::Permission;
use super::super::request::{PathIter, Request};
use super::super::response::HttpResponse;
use super::error::DispatchError;


//------------ /api/v1/ta ----------------------------------------------------

pub async fn dispatch(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("proxy") => proxy(request, path).await,
        Some("signer") => signer(request, path).await,
        _ => Ok(HttpResponse::not_found())
    }
}


//------------ /api/v1/proxy -------------------------------------------------

async fn proxy(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("children") => proxy_children(request, path).await,
        Some("id") => proxy_id(request, path),
        Some("init") => proxy_init(request, path),
        Some("repo") => proxy_repo(request, path).await,
        _ => Ok(HttpResponse::not_found())
    }
}


//------------ /api/v1/proxy/children ----------------------------------------

async fn proxy_children(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.parse_opt_next()? {
        None => proxy_children_index(request).await,
        Some(child) => proxy_children_child(request, path, child),
    }
}

async fn proxy_children_index(
    request: Request<'_>,
) -> Result<HttpResponse, DispatchError> {
    match *request.method() {
        Method::GET => {
            let (request, _) = request.proceed_permitted(
                Permission::CaAdmin, None
            )?;
            request.empty()?;
            Err(Error::NotImplemented.into())
        }
        Method::POST => {
            let (request, auth) = request.proceed_permitted(
                Permission::CaAdmin, None
            )?;
            let (server, child) = request.json().await?;
            server.krill().ta_proxy_children_add(child, auth.actor())?;
            Ok(HttpResponse::ok())
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

fn proxy_children_child(
    request: Request<'_>,
    mut path: PathIter<'_>,
    child: ChildHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        None => proxy_children_child_index(request, child),
        Some("parent_response.json") => {
            proxy_children_child_response(request, path, child)
        }
        Some("parent_response.xml") => {
            proxy_children_child_response_xml(request, path, child)
        }
        _ => Ok(HttpResponse::not_found())
    }
}

fn proxy_children_child_index(
    request: Request<'_>,
    _child: ChildHandle,
) -> Result<HttpResponse, DispatchError> {
    match *request.method() {
        Method::POST => {
            request.proceed_permitted(Permission::CaAdmin, None)?;
            // Ignore body for now.
            Err(Error::NotImplemented.into())
        }
        Method::DELETE => {
            let (request, _) = request.proceed_permitted(
                Permission::CaAdmin, None
            )?;
            request.empty()?;
            Err(Error::NotImplemented.into())
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

fn proxy_children_child_response(
    request: Request<'_>,
    path: PathIter<'_>,
    child: ChildHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaAdmin, None
    )?;
    let server = request.empty()?;
    Ok(HttpResponse::json(
        &server.krill().ca_parent_response(&ta_handle(), child)?
    ))
}

fn proxy_children_child_response_xml(
    request: Request<'_>,
    path: PathIter<'_>,
    child: ChildHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaAdmin, None
    )?;
    let server = request.empty()?;
    Ok(HttpResponse::xml(
        server.krill().ca_parent_response(&ta_handle(), child)?.to_xml_vec()
    ))
}


//------------ /api/v1/proxy/init --------------------------------------------

fn proxy_init(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaAdmin, None
    )?;
    let server = request.empty()?;
    Ok(HttpResponse::json(
        &server.krill().ta_proxy_init()?
    ))
}


//------------ /api/v1/proxy/id ----------------------------------------------

fn proxy_id(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaAdmin, None
    )?;
    let server = request.empty()?;
    Ok(HttpResponse::json(
        &server.krill().ta_proxy_id()?
    ))
}


//------------ /api/v1/proxy/repo --------------------------------------------

async fn proxy_repo(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        None => proxy_repo_index(request).await,
        Some("request.json") => proxy_repo_request(request, path),
        Some("request.xml") => proxy_repo_request_xml(request, path),
        _ => Ok(HttpResponse::not_found())
    }
}

async fn proxy_repo_index(
    request: Request<'_>,
) -> Result<HttpResponse, DispatchError> {
    match *request.method() {
        Method::GET => {
            let (request, _) = request.proceed_permitted(
                Permission::CaAdmin, None
            )?;
            let server = request.empty()?;
            Ok(HttpResponse::json(
                &server.krill().ta_proxy_repository_contact()?
            ))
        }
        Method::POST => {
            let (request, auth) = request.proceed_permitted(
                Permission::CaAdmin, None
            )?;
            let (server, contact) = request.json().await?;
            server.krill().ta_proxy_repository_update(contact, auth.actor())?;
            Ok(HttpResponse::ok())
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

fn proxy_repo_request(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(Permission::CaAdmin, None)?;
    let server = request.empty()?;
    Ok(HttpResponse::json(
        &server.krill().ta_proxy_publisher_request()?
    ))
}

fn proxy_repo_request_xml(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(Permission::CaAdmin, None)?;
    let server = request.empty()?;
    Ok(HttpResponse::xml(
        server.krill().ta_proxy_publisher_request()?.to_xml_vec()
    ))
}


//------------ /api/v1/signer-------------------------------------------------

async fn signer(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("add") => signer_add(request, path).await,
        Some("request") => signer_request(request, path),
        Some("response") => signer_response(request, path).await,
        Some("update") => signer_update(request, path).await,
        _ => Ok(HttpResponse::not_found())
    }
}

async fn signer_add(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, auth) = request.proceed_permitted(
        Permission::CaAdmin, None
    )?;
    let (server, info) = request.json().await?;
    server.krill().ta_proxy_signer_add(info, auth.actor())?;
    Ok(HttpResponse::ok())
}

fn signer_request(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    match *request.method() {
        Method::GET => {
            let (request, _) = request.proceed_permitted(
                Permission::CaAdmin, None
            )?;
            let server = request.empty()?;
            Ok(HttpResponse::json(
                &server.krill().ta_proxy_signer_get_request()?
            ))
        }
        Method::POST => {
            let (request, auth) = request.proceed_permitted(
                Permission::CaAdmin, None
            )?;
            let server = request.empty()?;
            Ok(HttpResponse::json(
                &server.krill().ta_proxy_signer_make_request(
                    auth.actor()
                )?
            ))
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

async fn signer_response(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, auth) = request.proceed_permitted(
        Permission::CaAdmin, None
    )?;
    let (server, response) = request.json().await?;
    server.krill().ta_proxy_signer_process_response(response, auth.actor())?;
    Ok(HttpResponse::ok())
}

async fn signer_update(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, auth) = request.proceed_permitted(
        Permission::CaAdmin, None
    )?;
    let (server, info) = request.json().await?;
    server.krill().ta_proxy_signer_update(info, auth.actor())?;
    Ok(HttpResponse::ok())
}

