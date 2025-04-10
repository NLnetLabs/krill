//! `/api/v1/cas`

use bytes::Bytes;
use hyper::Method;
use rpki::ca::idexchange::{
    CaHandle, ChildHandle, ParentHandle, ParentResponse,
    RepositoryResponse,
};
use crate::api::admin::{ApiRepositoryContact, ParentCaReq, RepositoryContact};
use crate::api::aspa::AspaDefinitionUpdates;
use crate::api::bgp::BgpAnalysisAdvice;
use crate::api::ca::{CertAuthList, CertAuthSummary};
use crate::api::import::ImportChild;
use crate::api::history::CommandHistoryCriteria;
use crate::api::roa::RoaConfigurationUpdates;
use crate::commons::error::Error;
use crate::commons::eventsourcing::AggregateStoreError;
use super::super::auth::Permission;
use super::super::request::{PathIter, Request};
use super::super::response::HttpResponse;
use super::error::DispatchError;


//------------ /api/v1/cas ---------------------------------------------------

pub async fn dispatch(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.parse_opt_next()? {
        None => index(request).await,
        Some(handle) => ca(request, path, handle).await,
    }
}

async fn index(
    request: Request<'_>,
) -> Result<HttpResponse, DispatchError> {
    match *request.method() {
        Method::GET => index_get(request),
        Method::POST => index_post(request).await,
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

fn index_get(
    request: Request<'_>,
) -> Result<HttpResponse, DispatchError> {
    let (request, auth) = request.proceed_unchecked();
    let server = request.empty()?;

    Ok(HttpResponse::json(
        &CertAuthList {
            cas: {
                server.krill().ca_handles()?.filter_map(|handle| {
                    auth.has_permission(
                        Permission::CaRead, Some(&handle)
                    ).then_some(CertAuthSummary { handle })
                }).collect()
            }
        }
    ))
}

async fn index_post(
    request: Request<'_>,
) -> Result<HttpResponse, DispatchError> {
    let (request, _) = request.proceed_permitted(
        Permission::CaCreate, None
    )?;
    let (server, init) = request.read_json().await?;
    server.krill().ca_init(init)?;
    Ok(HttpResponse::ok())
}


//------------ /api/v1/cas/{ca} ----------------------------------------------

pub async fn ca(
    request: Request<'_>,
    mut path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    request.check_permission(Permission::CaRead, Some(&ca))?;

    match path.next() {
        None => ca_index(request, ca).await,
        Some("aspas") => aspas(request, path, ca).await,
        Some("bgpsec") => bgpsec(request, path, ca).await,
        Some("children") => children(request, path, ca).await,
        Some("history") => history(request, path, ca),
        Some("id") => id(request, path, ca),
        Some("issues") => issues(request, path, ca),
        Some("keys") => keys(request, path, ca),
        Some("parents") => parents(request, path, ca).await,
        Some("repo") => repo(request, path, ca).await,
        Some("routes") => routes(request, path, ca).await,
        Some("stats") => stats(request, path, ca),
        Some("sync") => sync(request, path, ca),
        _ => Ok(HttpResponse::not_found())
    }
}

async fn ca_index(
    request: Request<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match *request.method() {
        Method::GET => {
            let (request, _) = request.proceed_permitted(
                Permission::CaRead, Some(&ca)
            )?;
            let server = request.empty()?;
            Ok(HttpResponse::json(
                &server.krill().ca_info(&ca)?
            ))
        }
        Method::DELETE => {
            let (request, auth) = request.proceed_permitted(
                Permission::CaDelete, Some(&ca)
            )?;
            let server = request.empty()?;
            server.krill().ca_delete(&ca, auth.actor()).await?;
            Ok(HttpResponse::ok())
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}


//------------ /api/v1/cas/{ca}/aspas ----------------------------------------

async fn aspas(
    request: Request<'_>,
    mut path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        None => aspas_index(request, ca).await,
        Some("as") => aspas_as(request, path, ca).await,
        _ => Ok(HttpResponse::not_found())
    }
}

async fn aspas_index(
    request: Request<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match *request.method() {
        Method::GET => {
            let (request, _) = request.proceed_permitted(
                Permission::AspasRead, Some(&ca)
            )?;
            let server = request.empty()?;
            Ok(HttpResponse::json(
                &server.krill().ca_aspas_definitions_show(&ca)?
            ))
        }
        Method::POST => {
            let (request, auth) = request.proceed_permitted(
                Permission::AspasUpdate, Some(&ca)
            )?;
            let (server, updates) = request.read_json().await?;
            server.krill().ca_aspas_definitions_update(
                ca, updates, auth.actor(),
            )?;
            Ok(HttpResponse::ok())
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

async fn aspas_as(
    request: Request<'_>,
    mut path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    let customer = path.parse_next()?;
    path.check_exhausted()?;
    match *request.method() {
        Method::POST => {
            let (request, auth) = request.proceed_permitted(
                Permission::AspasUpdate, Some(&ca)
            )?;
            let (server, update) = request.read_json().await?;
            server.krill().ca_aspas_update_aspa(
                ca, customer, update, auth.actor()
            )?;
            Ok(HttpResponse::ok())
        }
        Method::DELETE => {
            let (request, auth) = request.proceed_permitted(
                Permission::AspasUpdate, Some(&ca)
            )?;
            let server = request.empty()?;
            server.krill().ca_aspas_definitions_update(
                ca,
                AspaDefinitionUpdates {
                    add_or_replace: Vec::new(),
                    remove: vec![customer]
                },
                auth.actor(),
            )?;
            Ok(HttpResponse::ok())
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}


//------------ /api/v1/cas/{ca}/bgpsec ---------------------------------------

async fn bgpsec(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    match *request.method() {
        Method::GET => {
            let (request, _) = request.proceed_permitted(
                Permission::BgpsecRead, Some(&ca)
            )?;
            let server = request.empty()?;
            Ok(HttpResponse::json(
                &server.krill().ca_bgpsec_definitions_show(&ca)?
            ))
        }
        Method::POST => {
            let (request, auth) = request.proceed_permitted(
                Permission::BgpsecUpdate, Some(&ca)
            )?;
            let (server, updates) = request.read_json().await?;
            server.krill().ca_bgpsec_definitions_update(
                ca, updates, auth.actor()
            )?;
            Ok(HttpResponse::ok())
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}


//------------ /api/v1/cas/{ca}/children -------------------------------------

async fn children(
    request: Request<'_>,
    mut path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.parse_opt_next()? {
        None => children_index(request, ca).await,
        Some(child) => children_child(request, path, ca, child).await,
    }
}

async fn children_index(
    request: Request<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    request.check_post()?;
    let (request, auth) = request.proceed_permitted(
        Permission::CaUpdate, Some(&ca)
    )?;
    let (server, child_req) = request.read_json().await?;
    Ok(HttpResponse::json(
        &server.krill().ca_add_child(&ca, child_req, auth.actor())?
    ))
}

async fn children_child(
    request: Request<'_>,
    mut path: PathIter<'_>,
    ca: CaHandle,
    child: ChildHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        None => children_child_index(request, ca, child).await,
        Some("contact") | Some("parent_response.json") => {
            children_child_contact(request, path, ca, child)
        }
        Some("parent_response.xml") => {
            children_child_contact_xml(request, path, ca, child)
        }
        Some("export") => children_child_export(request, path, ca, child),
        Some("import") => {
            children_child_import(request, path, ca, child).await
        }
        _ => Ok(HttpResponse::not_found())
    }
}

async fn children_child_index(
    request: Request<'_>,
    ca: CaHandle,
    child: ChildHandle,
) -> Result<HttpResponse, DispatchError> {
    match *request.method() {
        Method::GET => {
            let (request, _) = request.proceed_permitted(
                Permission::CaRead, Some(&ca)
            )?;
            let server = request.empty()?;
            Ok(HttpResponse::json(
                &server.krill().ca_child_show(&ca, &child)?
            ))
        }
        Method::POST => {
            let (request, auth) = request.proceed_permitted(
                Permission::CaUpdate, Some(&ca)
            )?;
            let (server, child_req) = request.read_json().await?;
            server.krill().ca_child_update(
                &ca, child, child_req, auth.actor()
            )?;
            Ok(HttpResponse::ok())
        }
        Method::DELETE => {
            let (request, auth) = request.proceed_permitted(
                Permission::CaUpdate, Some(&ca)
            )?;
            let server = request.empty()?;
            server.krill().ca_child_remove(&ca, child, auth.actor())?;
            Ok(HttpResponse::ok())
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

fn children_child_contact(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
    child: ChildHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaRead, Some(&ca)
    )?;
    let server = request.empty()?;
    Ok(HttpResponse::json(
        &server.krill().ca_parent_response(&ca, child)?
    ))
}

fn children_child_contact_xml(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
    child: ChildHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaRead, Some(&ca)
    )?;
    let server = request.empty()?;
    let res = server.krill().ca_parent_response(&ca, child)?;
    Ok(HttpResponse::xml(res.to_xml_vec()))
}

fn children_child_export(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
    child: ChildHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaRead, Some(&ca)
    )?;
    let server = request.empty()?;
    Ok(HttpResponse::json(
        &server.krill().ca_child_export(&ca, &child)?
    ))
}

async fn children_child_import(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
    child: ChildHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, auth) = request.proceed_permitted(
        Permission::CaAdmin, Some(&ca)
    )?;
    let (server, import) = request.read_json::<ImportChild>().await?;
    if import.name != child {
        return Ok(HttpResponse::response_from_error(
            Error::CaChildImportHandleMismatch {
                path: child, body: import.name
            }
        ))
    }
    server.krill().ca_child_import(&ca, import, auth.actor())?;
    Ok(HttpResponse::ok())
}


//------------ /api/v1/cas/{ca}/history --------------------------------------

fn history(
    request: Request<'_>,
    mut path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("commands") => history_commands(request, path, ca),
        Some("details") => history_details(request, path, ca),
        _ => Ok(HttpResponse::not_found())
    }
}

fn history_commands(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    let mut path = path.strip_trailing_slash();
    let rows_limit = Some(path.parse_opt_next()?.unwrap_or(100));
    let offset = path.parse_opt_next()?.unwrap_or(0);
    let after = path.parse_opt_next()?;
    let before = path.parse_opt_next()?;
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaRead, Some(&ca)
    )?;
    let server = request.empty()?;

    Ok(HttpResponse::json(
        &server.krill().ca_history(
            &ca,
            CommandHistoryCriteria {
                before, after, offset, rows_limit,
                .. Default::default()
            }
        )?
    ))
}

fn history_details(
    request: Request<'_>,
    mut path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    let version = path.parse_next()?;
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaRead, Some(&ca)
    )?;
    let server = request.empty()?;

    Ok(HttpResponse::json(
        &server.krill().ca_command_details(&ca, version).map_err(|err| {
            match err {
                Error::AggregateStoreError(
                    AggregateStoreError::UnknownCommand(..)
                ) => {
                    HttpResponse::not_found()
                },
                err => {
                    HttpResponse::response_from_error(err)
                }
            }
        })?
    ))
}


//------------ /api/v1/cas/{ca}/id -------------------------------------------

fn id(
    request: Request<'_>,
    mut path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        None => id_index(request, ca),
        Some("child_request.json") => {
            id_child_request_json(request, path, ca)
        }
        Some("child_request.xml") => id_child_request_xml(request, path, ca),
        Some("publisher_request.json") => {
            id_publisher_request_json(request, path, ca)
        }
        Some("publisher_request.xml") => {
            id_publisher_request_xml(request, path, ca)
        }
        _ => Ok(HttpResponse::not_found())
    }
}

fn id_index(
    request: Request<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    request.check_post()?;
    let (request, auth) = request.proceed_permitted(
        Permission::CaUpdate, Some(&ca)
    )?;
    let server = request.empty()?;
    server.krill().ca_update_id(ca, auth.actor())?;
    Ok(HttpResponse::ok())
}

fn id_child_request_json(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaRead, Some(&ca)
    )?;
    let server = request.empty()?;
    Ok(HttpResponse::json(
        &server.krill().ca_child_req(&ca)?
    ))
}

fn id_child_request_xml(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaRead, Some(&ca)
    )?;
    let server = request.empty()?;
    Ok(HttpResponse::xml(
        server.krill().ca_child_req(&ca)?.to_xml_vec()
    ))
}

fn id_publisher_request_json(
    request: Request,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaRead, Some(&ca)
    )?;
    let server = request.empty()?;
    Ok(HttpResponse::json(
        &server.krill().ca_publisher_req(&ca)?
    ))
}

fn id_publisher_request_xml(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaRead, Some(&ca)
    )?;
    let server = request.empty()?;
    Ok(HttpResponse::xml(
        server.krill().ca_publisher_req(&ca)?.to_xml_vec()
    ))
}


//------------ /api/v1/cas/{ca}/issues ---------------------------------------

fn issues(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaRead, Some(&ca)
    )?;
    let server = request.empty()?;
    Ok(HttpResponse::json(
        &server.krill().ca_issues(&ca)?
    ))
}


//------------ /api/v1/cas/{ca}/keys -----------------------------------------

fn keys(
    request: Request<'_>,
    mut path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("roll_init") => keys_roll_init(request, path, ca),
        Some("roll_activate") => keys_roll_activate(request, path, ca),
        _ => Ok(HttpResponse::not_found())
    }
}

fn keys_roll_init(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, auth) = request.proceed_permitted(
        Permission::CaUpdate, Some(&ca)
    )?;
    let server = request.empty()?;
    server.krill().ca_keyroll_init(ca, auth.actor())?;
    Ok(HttpResponse::ok())
}

fn keys_roll_activate(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, auth) = request.proceed_permitted(
        Permission::CaUpdate, Some(&ca)
    )?;
    let server = request.empty()?;
    server.krill().ca_keyroll_activate(ca, auth.actor())?;
    Ok(HttpResponse::ok())
}


//------------ /api/v1/cas/{ca}/parents --------------------------------------

async fn parents(
    request: Request<'_>,
    mut path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.parse_opt_next()? {
        None => parents_index(request, ca).await,
        Some(parent) => parents_parent(request, path, ca, parent).await,
    }
}

async fn parents_index(
    request: Request<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match *request.method() {
        Method::GET => {
            let (request, _) = request.proceed_permitted(
                Permission::CaRead, Some(&ca)
            )?;
            let server = request.empty()?;
            Ok(HttpResponse::json(
                &server.krill().ca_status(&ca)?.into_parents()
            ))
        }
        Method::POST => {
            let (request, auth) = request.proceed_permitted(
                Permission::CaUpdate, Some(&ca)
            )?;
            let (server, bytes) = request.read_bytes().await?;
            let parent_req = extract_parent_ca_req(&ca, bytes, None)?;
            server.krill().ca_parent_add_or_update(
                ca, parent_req, auth.actor()
            ).await?;
            Ok(HttpResponse::ok())
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

async fn parents_parent(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
    parent: ParentHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    match *request.method() {
        Method::GET => {
            let (request, _) = request.proceed_permitted(
                Permission::CaRead, Some(&ca)
            )?;
            let server = request.empty()?;
            Ok(HttpResponse::json(
                &server.krill().ca_my_parent_contact(&ca, &parent)?
            ))
        }
        Method::POST => {
            let (request, auth) = request.proceed_permitted(
                Permission::CaUpdate, Some(&ca)
            )?;
            let (server, bytes) = request.read_bytes().await?;
            let parent_req = extract_parent_ca_req(
                &ca, bytes, Some(parent)
            )?;
            server.krill().ca_parent_add_or_update(
                ca, parent_req, auth.actor()
            ).await?;
            Ok(HttpResponse::ok())
        }
        Method::DELETE => {
            let (request, auth) = request.proceed_permitted(
                Permission::CaUpdate, Some(&ca)
            )?;
            let server = request.empty()?;
            server.krill().ca_parent_remove(ca, parent, auth.actor()).await?;
            Ok(HttpResponse::ok())
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

fn extract_parent_ca_req(
    ca: &CaHandle,
    bytes: Bytes,
    parent_override: Option<ParentHandle>,
) -> Result<ParentCaReq, Error> {
    // We distinguis between XML and JSON by looking at the first
    // non-whitespace character which should be '<' for XML.
    let bytes = bytes.trim_ascii_start();
    if bytes.first().copied() == Some(b'<') {
        let response = ParentResponse::parse(bytes).map_err(|err| {
            Error::CaParentResponseInvalid(
                ca.clone(),
                err.to_string(),
            )
        })?;

        let parent_name = parent_override.unwrap_or_else(|| {
            response.parent_handle().clone()
        });

        Ok(ParentCaReq { handle: parent_name, response })
    }
    else {
        let req: ParentCaReq = serde_json::from_slice(bytes).map_err(
            Error::JsonError
        )?;
        if let Some(parent_override) = parent_override {
            if req.handle != parent_override {
                return Err(Error::Custom(format!(
                    "Used different parent names on path ({}) and \
                     submitted JSON ({}) for adding/updating a parent",
                    parent_override,
                    req.handle
                )));
            }
        }
        Ok(req)
    }
}


//------------ /api/v1/cas/{ca}/repo -----------------------------------------

async fn repo(
    request: Request<'_>,
    mut path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        None => repo_index(request, ca).await,
        Some("status") => repo_status(request, path, ca),
        _ => Ok(HttpResponse::not_found())
    }
}

async fn repo_index(
    request: Request<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match *request.method() {
        Method::GET => {
            let (request, _) = request.proceed_permitted(
                Permission::CaRead, Some(&ca)
            )?;
            let server = request.empty()?;
            Ok(HttpResponse::json(
                &server.krill().ca_repo_details(&ca)?
            ))
        }
        Method::POST => {
            let (request, auth) = request.proceed_permitted(
                Permission::CaUpdate, Some(&ca)
            )?;
            let (server, update) = request.read_bytes().await?;
            let update = extract_repository_contact(&ca, update)?;
            server.krill().ca_repo_update(ca, update, auth.actor()).await?;
            Ok(HttpResponse::ok())
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

pub fn extract_repository_contact(
    ca: &CaHandle,
    bytes: Bytes,
) -> Result<RepositoryContact, Error> {
    // We distinguis between XML and JSON by looking at the first
    // non-whitespace character which should be '<' for XML.
    let bytes = bytes.trim_ascii_start();
    if bytes.first().copied() == Some(b'<') {
        let response = RepositoryResponse::parse(bytes).map_err(|err| {
            Error::CaRepoResponseInvalid(
                ca.clone(),
                err.to_string(),
            )
        })?;
        RepositoryContact::try_from_response(response).map_err(|err| {
            Error::CaRepoResponseInvalid(ca.clone(), err.to_string())
        })
    }
    else {
        let api_contact: ApiRepositoryContact = serde_json::from_slice(
            bytes
        ).map_err(Error::JsonError)?;
        RepositoryContact::try_from_response(api_contact.repository_response)
    }
}

fn repo_status(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaRead, Some(&ca)
    )?;
    let server = request.empty()?;
    Ok(HttpResponse::json(
        &server.krill().ca_status(&ca)?.into_repo()
    ))
}


//------------ /api/v1/cas/{ca}/routes ---------------------------------------

async fn routes(
    request: Request<'_>,
    mut path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        None => routes_index(request, ca).await,
        Some("try") => routes_try(request, path, ca).await,
        Some("analysis") => routes_analysis(request, path, ca).await,
        _ => Ok(HttpResponse::not_found())
    }
}

async fn routes_index(
    request: Request<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match *request.method() {
        Method::GET => {
            let (request, _) = request.proceed_permitted(
                Permission::RoutesRead, Some(&ca)
            )?;
            let server = request.empty()?;
            Ok(HttpResponse::json(
                &server.krill().ca_routes_show(&ca)?
            ))
        }
        Method::POST => {
            let (request, auth) = request.proceed_permitted(
                Permission::RoutesUpdate, Some(&ca)
            )?;
            let (server, updates) = request.read_json().await?;
            server.krill().ca_routes_update(ca, updates, auth.actor())?;
            Ok(HttpResponse::ok())
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}

async fn routes_try(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, auth) = request.proceed_permitted(
        Permission::RoutesUpdate, Some(&ca)
    )?;
    let (server, mut updates)
        = request.read_json::<RoaConfigurationUpdates>().await?;
    let effect = server.krill().ca_routes_bgp_dry_run(
        &ca, updates.clone()
    ).await?;
    if effect.contains_invalids() {
        updates.set_explicit_max_length();
        let resources = updates.affected_prefixes();
        let suggestion = server.krill().ca_routes_bgp_suggest(
            &ca, Some(resources)
        ).await?;
        Ok(HttpResponse::json(
            &BgpAnalysisAdvice {
                effect, suggestion,
            }
        ))
    }
    else {
        server.krill().ca_routes_update(ca, updates, auth.actor())?;
        Ok(HttpResponse::ok())
    }
}

async fn routes_analysis(
    request: Request<'_>,
    mut path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("full") => routes_analysis_full(request, path, ca).await,
        Some("dryrun") => routes_analysis_dryrun(request, path, ca).await,
        Some("suggest") => routes_analysis_suggest(request, path, ca).await,
        _ => Ok(HttpResponse::not_found())
    }
}

async fn routes_analysis_full(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(
        Permission::RoutesAnalysis, Some(&ca)
    )?;
    let server = request.empty()?;
    Ok(HttpResponse::json(
        &server.krill().ca_routes_bgp_analysis(&ca).await?
    ))
}

async fn routes_analysis_dryrun(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, _) = request.proceed_permitted(
        Permission::RoutesAnalysis, Some(&ca)
    )?;
    let (server, updates) = request.read_json().await?;
    Ok(HttpResponse::json(
        &server.krill().ca_routes_bgp_dry_run(&ca, updates).await?
    ))
}

async fn routes_analysis_suggest(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    match *request.method() {
        Method::GET => {
            let (request, _) = request.proceed_permitted(
                Permission::RoutesAnalysis, Some(&ca)
            )?;
            let server = request.empty()?;
            Ok(HttpResponse::json(
                &server.krill().ca_routes_bgp_suggest(&ca, None).await?
            ))
        }
        Method::POST => {
            let (request, _) = request.proceed_permitted(
                Permission::RoutesAnalysis, Some(&ca)
            )?;
            let (server, resources) = request.read_json().await?;
            Ok(HttpResponse::json(
                &server.krill().ca_routes_bgp_suggest(
                    &ca, Some(resources)
                ).await?
            ))
        }
        _ => Ok(HttpResponse::method_not_allowed())
    }
}


//------------ /api/v1/cas/{ca}/stats ----------------------------------------

fn stats(
    request: Request<'_>,
    mut path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("children") => stats_children(request, path, ca),
        _ => Ok(HttpResponse::not_found())
    }
}

fn stats_children(
    request: Request<'_>,
    mut path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("connections") => stats_children_connections(request, path, ca),
        _ => Ok(HttpResponse::not_found())
    }
}

fn stats_children_connections(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaRead, Some(&ca)
    )?;
    let server = request.empty()?;
    Ok(HttpResponse::json(
        &server.krill().ca_stats_child_connections(&ca)?
    ))
}


//------------ /api/v1/cas/{ca}/sync -----------------------------------------

fn sync(
    request: Request<'_>,
    mut path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("parents") => sync_parents(request, path, ca),
        Some("repo") => sync_repo(request, path, ca),
        _ => Ok(HttpResponse::not_found())
    }
}

fn sync_parents(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaUpdate, Some(&ca)
    )?;
    let server = request.empty()?;
    server.krill().cas_refresh_single(ca)?;
    Ok(HttpResponse::ok())
}

fn sync_repo(
    request: Request<'_>,
    path: PathIter<'_>,
    ca: CaHandle,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, _) = request.proceed_permitted(
        Permission::CaUpdate, Some(&ca)
    )?;
    let server = request.empty()?;
    server.krill().cas_repo_sync_single(&ca)?;
    Ok(HttpResponse::ok())
}

