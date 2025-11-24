//! `/api/v1/ta`

use super::super::request::{PathIter, Request};
use super::super::response::HttpResponse;
use super::error::DispatchError;


//------------ /stats --------------------------------------------------------

pub async fn dispatch(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("info") => info(request, path),
        Some("repo") => repo(request, path),
        Some("cas") => cas(request, path).await,
        _ => Ok(HttpResponse::not_found())
    }
}


//------------ /stats/info ---------------------------------------------------

fn info(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_unchecked();
    let server = request.empty()?;
    Ok(HttpResponse::json(&server.server_info()))
}


//------------ /stats/repo ---------------------------------------------------

fn repo(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_unchecked();
    let server = request.empty()?;
    Ok(HttpResponse::json(&server.krill().repo_stats()?))
}


//------------ /stats/cas ----------------------------------------------------

async fn cas(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_unchecked();
    let server = request.empty()?;
    Ok(HttpResponse::json(&server.krill().cas_stats()?))
}

