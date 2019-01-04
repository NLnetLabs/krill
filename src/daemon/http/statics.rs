//! Delivery of static content. See also:
//! https://github.com/railwayhistory/railsite/blob/master/src/statics.rs

use actix_web::{Error, HttpRequest, HttpResponse, Responder};
use actix_web::http::StatusCode;

/// Register static resources at compile time. Specify the app first, and
/// then for each resource:
/// * the path
/// * the mime type
/// * an etag value
///
/// Note the etag cannot be dynamically derived at compile time until
/// 'const fn' are stable. So, be sure to use a value here that is unique
/// to this resource, and this version of this resource. E.g. calculate its
/// hash on the command line and use that in a &str.
macro_rules! statics {
    ( $app:expr, $( $path:expr => $mime:expr => $etag:expr, )* ) => {{
        $app
        $(
            .resource(concat!("/static/", $path), |r| {
                static CONTENT: ::daemon::http::statics::StaticContent
                                    = ::daemon::http::statics::StaticContent {
                    content: include_bytes!(
                        concat!("../../../static/",$path)
                    ),
                    etag: $etag,
                    ctype: $mime
                };
                r.get().f(|_| &CONTENT)
            })
        )*
    }}
}


//------------ StaticContent -------------------------------------------------

pub struct StaticContent {
    pub content: &'static [u8],
    pub etag: &'static str,
    pub ctype: &'static [u8],
}


impl Responder for &'static StaticContent {
    type Item = HttpResponse;
    type Error = Error;

    fn respond_to<S>(
        self,
        req: &HttpRequest<S>
    ) -> Result<HttpResponse, Error> {

        if let Some(etag) = req.headers().get("If-None-Match") {
            if etag == self.etag {
                return Ok(
                    req.build_response(StatusCode::NOT_MODIFIED).finish()
                )
            }
        }

        Ok(req
            .build_response(StatusCode::OK)
            .content_type(self.ctype)
            .header("etag", self.etag)
            .header("Cache-Control", "max-age: 86400") // cache for a day
            .body(self.content)
        )
    }
}