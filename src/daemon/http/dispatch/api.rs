//! `/api`

use super::super::auth::Permission;
use super::super::request::{PathIter, Request};
use super::super::response::HttpResponse;
use super::error::DispatchError;


pub async fn dispatch(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("v1") => api_v1(request, path).await,
        _ => Ok(HttpResponse::not_found())
    }
}

async fn api_v1(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("authorized") => authorized(request, path),
        other => {
            request.check_permission(Permission::Login, None)?;
            match other {
                Some("bulk") => super::bulk::dispatch(request, path).await,
                Some("cas") => super::cas::dispatch(request, path).await,
                Some("pubd") => super::pubd::dispatch(request, path).await,
                Some("ta") => super::ta::dispatch(request, path).await,
                _ => Ok(HttpResponse::not_found())
            }
        }
    }
}

fn authorized(
    request: Request, path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    request.check_permission(Permission::Login, None).map_err(|err| {
        err.with_benign(true)
    })?;
    Ok(HttpResponse::ok())
}

