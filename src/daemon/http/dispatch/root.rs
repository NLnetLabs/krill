//! Root level.

use std::fs;
use super::super::request::{Request, PathIter};
use super::super::response::HttpResponse;
use super::error::DispatchError;


//------------ / -------------------------------------------------------------

pub async fn dispatch_request(
    request: Request<'_>,
    mut path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("") => index(request),
        Some("api") => super::api::dispatch(request, path).await,
        Some("assets") => assets(request, path),
        Some("auth") => super::auth::dispatch(request, path).await,
        Some("health") => health(request, path),
        Some("metrics") => super::metrics::dispatch(request, path).await,
        Some("rfc8181") => rfc8181(request, path).await,
        Some("rfc6492") => rfc6492(request, path).await,
        Some("rrdp") => rrdp(request, path),
        Some("stats") => super::stats::dispatch(request, path).await,
        Some("ta") => ta(request, path),
        Some("testbed.tal") => tal(request, path),
        Some("testbed") => super::testbed::dispatch(request, path).await,
        Some("ui") => ui(request, path),

        // statics
        //
        _ => Ok(HttpResponse::not_found())
    }
}


//------------ / -------------------------------------------------------------

fn index(
    request: Request<'_>
) -> Result<HttpResponse, DispatchError> {
    request.check_get()?;
    let (request, _) = request.proceed_unchecked();
    request.empty()?;
    Ok(HttpResponse::found("/ui"))
}


//------------ /health -------------------------------------------------------

fn health(
    request: Request<'_>, path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_unchecked();
    request.empty()?;
    Ok(HttpResponse::ok())
}


//------------ /rfc8181 ------------------------------------------------------

async fn rfc8181(
    request: Request<'_>, path: PathIter<'_>
) -> Result<HttpResponse, DispatchError> {
    // We need to allow trailing slashes for compatibility.
    let mut path = path.strip_trailing_slash();

    let publisher = path.parse_next()?;
    path.check_exhausted()?;
    request.check_post()?;
    let (request, _) = request.proceed_unchecked();
    let (server, bytes) = request.read_rfc8181_bytes().await?;
    Ok(HttpResponse::rfc8181(
        server.old_krill().rfc8181(publisher, bytes)?
    ))
}


//------------ /rfc6492 ------------------------------------------------------

async fn rfc6492(
    request: Request<'_>, path: PathIter<'_>
) -> Result<HttpResponse, DispatchError> {
    // We need to allow trailing slashes for compatibility.
    let mut path = path.strip_trailing_slash();

    let ca = path.parse_next()?;
    path.check_exhausted()?;
    request.check_post()?;
    let user_agent = request.user_agent();
    let (request, auth) = request.proceed_unchecked();
    let (server, bytes) = request.read_rfc6492_bytes().await?;
    // XXX Using auth.actor() here doesn’t make much sense -- it likely will
    //     always be the anonymous actor. Maybe the CA manager should
    //     determine the actor when looking at the ID certificate?
    Ok(HttpResponse::rfc6492(
        server.old_krill().rfc6492(ca , bytes, user_agent, auth.actor())?
    ))
}


//------------ /ta -----------------------------------------------------------

fn ta(
    request: Request<'_>, mut path: PathIter<'_>
) -> Result<HttpResponse, DispatchError> {
    match path.next() {
        Some("ta.tal") => tal(request, path),
        Some("ta.cer") => ta_cer(request, path),
        _ => Ok(HttpResponse::not_found())
    }
}

fn tal(
    request: Request<'_>, path: PathIter<'_>
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_unchecked();
    let server = request.empty()?;
    Ok(HttpResponse::text(
        server.old_krill().ta_cert_details()?.tal.to_string()
    ))
}

fn ta_cer(
    request: Request<'_>, path: PathIter<'_>
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_unchecked();
    let server = request.empty()?;
    Ok(HttpResponse::cert(
        server.old_krill().ta_cert_details()?.cert.to_bytes()
    ))
}


//------------ /rrdp ---------------------------------------------------------

fn rrdp(
    request: Request<'_>, path: PathIter<'_>
) -> Result<HttpResponse, DispatchError> {
    request.check_get()?;
    let (request, _) = request.proceed_unchecked();
    let server = request.empty()?;
    let Some(remaining) = path.remaining() else {
        return Ok(HttpResponse::not_found())
    };
    let path = match server.old_krill().resolve_rrdp_request_path(remaining)? {
        Some(path) => path,
        None => {
            return Ok(HttpResponse::not_found())
        }
    };

    let cache_seconds = if remaining == "notification.xml" {
        60
    } else {
        86400
    };

    let buffer = match fs::read(&path) {
        Ok(file) => file,
        Err(_) => {
            return Ok(HttpResponse::not_found())
        }
    };
    Ok(HttpResponse::xml_with_cache(buffer, cache_seconds))
}


//------------ /ui -----------------------------------------------------------

fn ui(
    request: Request<'_>, _path: PathIter<'_>
) -> Result<HttpResponse, DispatchError> {
    // No check for exhausted since longer paths are totally legit.
    request.check_get()?;
    let (request, _) = request.proceed_unchecked();
    let _server = request.empty()?;
    Ok(HttpResponse::ok_with_body(
        assets::INDEX.media_type,
        assets::INDEX.content,
    ))
}


//------------ /assets -------------------------------------------------------

fn assets(
    request: Request<'_>, mut path: PathIter<'_>
) -> Result<HttpResponse, DispatchError> {
    let asset = {
        let Some(next) = path.next() else {
            return Ok(HttpResponse::not_found())
        };
        match assets::ASSETS.iter().find(|asset| {
            asset.path == next
        }) {
            Some(asset) => asset,
            None => return Ok(HttpResponse::not_found()),
        }
    };
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_unchecked();
    let _server = request.empty()?;
    Ok(HttpResponse::ok_with_body(
        asset.media_type,
        asset.content,
    ))
}

mod assets {
    include!(concat!(env!("OUT_DIR"), "/ui_assets.rs"));
}

