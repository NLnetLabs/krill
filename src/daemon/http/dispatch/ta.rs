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
        Some("id") => proxy_id(request, path).await,
        Some("init") => proxy_init(request, path).await,
        Some("repo") => proxy_repo(request, path).await,
        Some("signer") => proxy_signer(request, path).await,
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
        Some(child) => proxy_children_child(request, path, child).await,
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
            let (server, child) = request.read_json().await?;
            Ok(HttpResponse::json(
                &server.krill().ta_proxy_children_add(
                    child, auth.into_actor()
                ).await?
            ))
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

async fn proxy_children_child(
    request: Request<'_>,
    mut path: PathIter<'_>,
    child: ChildHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        None => proxy_children_child_index(request, child),
        Some("parent_response.json") => {
            proxy_children_child_response(request, path, child).await
        }
        Some("parent_response.xml") => {
            proxy_children_child_response_xml(request, path, child).await
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

async fn proxy_children_child_response(
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
        &server.krill().ca_parent_response(ta_handle(), child).await?
    ))
}

async fn proxy_children_child_response_xml(
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
        server.krill().ca_parent_response(
            ta_handle(), child
        ).await?.to_xml_vec()
    ))
}


//------------ /api/v1/proxy/init --------------------------------------------

async fn proxy_init(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaAdmin, None
    )?;
    let server = request.empty()?;
    server.krill().ta_proxy_init().await?;
    Ok(HttpResponse::ok())
}


//------------ /api/v1/proxy/id ----------------------------------------------

async fn proxy_id(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaAdmin, None
    )?;
    let server = request.empty()?;
    Ok(HttpResponse::json(
        &server.krill().ta_proxy_id().await?
    ))
}


//------------ /api/v1/proxy/repo --------------------------------------------

async fn proxy_repo(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        None => proxy_repo_index(request).await,
        Some("request.json") => proxy_repo_request(request, path).await,
        Some("request.xml") => proxy_repo_request_xml(request, path).await,
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
                &server.krill().ta_proxy_repository_contact().await?
            ))
        }
        Method::POST => {
            let (request, auth) = request.proceed_permitted(
                Permission::CaAdmin, None
            )?;
            let (server, update) = request.read_bytes().await?;
            let update = super::cas::extract_repository_contact(
                &ta_handle(), update
            )?;
            server.krill().ta_proxy_repository_update(
                update, auth.into_actor()
            ).await?;
            Ok(HttpResponse::ok())
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

async fn proxy_repo_request(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(Permission::CaAdmin, None)?;
    let server = request.empty()?;
    Ok(HttpResponse::json(
        &server.krill().ta_proxy_publisher_request().await?
    ))
}

async fn proxy_repo_request_xml(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(Permission::CaAdmin, None)?;
    let server = request.empty()?;
    Ok(HttpResponse::xml(
        server.krill().ta_proxy_publisher_request().await?.to_xml_vec()
    ))
}


//------------ /api/v1/proxy/signer ------------------------------------------

async fn proxy_signer(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("add") => proxy_signer_add(request, path).await,
        Some("request") => proxy_signer_request(request, path).await,
        Some("response") => proxy_signer_response(request, path).await,
        Some("update") => proxy_signer_update(request, path).await,
        _ => Ok(HttpResponse::not_found())
    }
}

async fn proxy_signer_add(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, auth) = request.proceed_permitted(
        Permission::CaAdmin, None
    )?;
    let (server, info) = request.read_json().await?;
    server.krill().ta_proxy_signer_add(info, auth.into_actor()).await?;
    Ok(HttpResponse::ok())
}

async fn proxy_signer_request(
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
                &server.krill().ta_proxy_signer_get_request().await?
            ))
        }
        Method::POST => {
            let (request, auth) = request.proceed_permitted(
                Permission::CaAdmin, None
            )?;
            let server = request.empty()?;
            Ok(HttpResponse::json(
                &server.krill().ta_proxy_signer_make_request(
                    auth.into_actor()
                ).await?
            ))
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

async fn proxy_signer_response(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, auth) = request.proceed_permitted(
        Permission::CaAdmin, None
    )?;
    let (server, response) = request.read_json().await?;
    server.krill().ta_proxy_signer_process_response(
        response, auth.into_actor()
    ).await?;
    Ok(HttpResponse::ok())
}

async fn proxy_signer_update(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, auth) = request.proceed_permitted(
        Permission::CaAdmin, None
    )?;
    let (server, info) = request.read_json().await?;
    server.krill().ta_proxy_signer_update(info, auth.into_actor()).await?;
    Ok(HttpResponse::ok())
}

