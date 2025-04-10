//! `/api/v1/bulk`

use crate::api::ca::AllCertAuthIssues;
use super::super::auth::Permission;
use super::super::request::{PathIter, Request};
use super::super::response::HttpResponse;
use super::error::DispatchError;


pub async fn dispatch(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("cas") => cas(request, path).await,
        _ => Ok(HttpResponse::not_found())
    }
}

async fn cas(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("import") => cas_import(request, path).await,
        Some("issues") => cas_issues(request, path),
        Some("sync") => cas_sync(request, path),
        Some("publish") => cas_publish(request, path),
        Some("force_publish") => cas_force_publish(request, path),
        Some("suspend") => cas_suspend(request, path),
        _ => Ok(HttpResponse::not_found())
    }
}

async fn cas_import(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, _) = request.proceed_permitted(Permission::CaAdmin, None)?;
    let (server, structure) = request.read_json().await?;
    server.krill().cas_import(structure).await?;
    Ok(HttpResponse::ok())
}

fn cas_issues(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, auth) = request.proceed_unchecked();
    let server = request.empty()?;

    let mut all_issues = AllCertAuthIssues::default();
    for ca in server.krill().ca_handles()? {
        if auth.has_permission(Permission::CaRead, Some(&ca)) {
            let issues = server.krill().ca_issues(&ca)?;
            if !issues.is_empty() {
                all_issues.cas.insert(ca, issues);
            }
        }
    }

    Ok(HttpResponse::json(&all_issues))
}

fn cas_sync(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("parent") => cas_sync_parent(request, path),
        Some("repo") => cas_sync_repo(request, path),
        _ => Ok(HttpResponse::not_found())
    }
}

fn cas_sync_parent(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, _) = request.proceed_permitted(Permission::CaAdmin, None)?;
    let server = request.empty()?;
    server.krill().cas_refresh_all()?;
    Ok(HttpResponse::ok())
}

fn cas_sync_repo(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, _) = request.proceed_permitted(Permission::CaAdmin, None)?;
    let server = request.empty()?;
    server.krill().cas_repo_sync_all()?;
    Ok(HttpResponse::ok())
}

fn cas_publish(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, _) = request.proceed_permitted(Permission::CaAdmin, None)?;
    let server = request.empty()?;
    server.krill().republish_all(false)?;
    Ok(HttpResponse::ok())
}

fn cas_force_publish(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, _) = request.proceed_permitted(Permission::CaAdmin, None)?;
    let server = request.empty()?;
    server.krill().republish_all(true)?;
    Ok(HttpResponse::ok())
}

fn cas_suspend(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_post()?;
    let (request, _) = request.proceed_permitted(Permission::CaAdmin, None)?;
    let server = request.empty()?;
    server.krill().cas_schedule_suspend_all()?;
    Ok(HttpResponse::ok())
}

