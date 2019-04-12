//! Delivery of ui content. See also:
//! https://github.com/railwayhistory/railsite/blob/master/src/statics.rs
use actix_web::{Error, HttpRequest, HttpResponse, Responder};
use actix_web::http::StatusCode;

/// Register ui resources at compile time. Specify the app first, and
/// then for each resource:
/// * the path
/// * the mime type
///
#[allow(unused_macros)]
macro_rules! statics {
    ( $app:expr, $( $path:expr => $mime:expr, )* ) => {{
        $app
        $(
            .resource(concat!("/ui/", $path), |r| {
                static CONTENT: ::http::statics::StaticContent
                                    = ::http::statics::StaticContent {
                    content: include_bytes!(
                        concat!("../../ui/dist/",$path)
                    ),
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
    pub ctype: &'static [u8],
}


impl Responder for &'static StaticContent {
    type Item = HttpResponse;
    type Error = Error;

    fn respond_to<S>(
        self,
        req: &HttpRequest<S>
    ) -> Result<HttpResponse, Error> {
        Ok(req
            .build_response(StatusCode::OK)
            .content_type(self.ctype)
            .header("Cache-Control", "max-age: 86400") // cache for a day
            .body(self.content)
        )
    }
}