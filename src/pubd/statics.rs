//! Delivery of static content. See also:
//! https://github.com/railwayhistory/railsite/blob/master/src/statics.rs

use actix_web::{Error, HttpRequest, HttpResponse, Responder};
use actix_web::http::StatusCode;

macro_rules! statics {
    ( $app:expr, $( $path:expr => $mime:expr, )* ) => {{
        $app
        $(
            .resource(concat!("/static/", $path), |r| {
                static CONTENT: ::pubd::statics::StaticContent
                                    = ::pubd::statics::StaticContent {
                    content: include_bytes!(concat!("../../static/", $path)),
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
            .body(self.content)
        )
    }
}