use hyper::{Method, StatusCode};

use crate::daemon::http::RoutingResult;
use crate::daemon::http::{HttpResponse, Request};

pub async fn statics(req: Request) -> RoutingResult {
    let res = match *req.method() {
        Method::GET => match req.path.full() {
            "/" => Ok(HttpResponse::new(
                hyper::Response::builder()
                    .status(StatusCode::FOUND)
                    .header("location", "/index.html")
                    .body(hyper::Body::empty())
                    .unwrap(),
            )),
            "/index.html" => Ok(HttpResponse::html(INDEX)),

            "/assets/favicon.f84116cb.ico" => Ok(HttpResponse::fav(FAVICON)),

            "/assets/index.86ec8eab.js" => Ok(HttpResponse::js(JS_INDEX)),

            "/assets/en.3ab0d1a7.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_ENGLISH)),
            "/assets/de.0c1879e3.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_GERMAN)),
            "/assets/es.ab1a0965.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_SPANISH)),
            "/assets/fr.07a7f086.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_FRENCH)),
            "/assets/gr.a1128018.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_GREEK)),
            "/assets/nl.e60332ba.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_DUTCH)),
            "/assets/pt.813d91fd.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_PORTUGUESE)),

            "/assets/index.c2dde177.css" => Ok(HttpResponse::css(CSS)),

            "/assets/check.3e734f78.svg" => Ok(HttpResponse::svg(SVG_CHECK)),
            "/assets/check-green.4525c79c.svg" => Ok(HttpResponse::svg(SVG_CHECK_GREEN)),
            "/assets/clipboard.4659ffea.svg" => Ok(HttpResponse::svg(SVG_CLIPBOARD)),
            "/assets/download.2dfead4c.svg" => Ok(HttpResponse::svg(SVG_DOWNLOAD)),
            "/assets/error.fd1fc7e1.svg" => Ok(HttpResponse::svg(SVG_ERROR)),
            "/assets/krill_logo_white.05224433.svg" => Ok(HttpResponse::svg(SVG_KRILL_LOGO)),
            "/assets/logout.c725fd2c.svg" => Ok(HttpResponse::svg(SVG_LOGOUT)),
            "/assets/plus.e8f1d18.svg" => Ok(HttpResponse::svg(SVG_PLUS)),
            "/assets/route-left.c88b44cb.svg" => Ok(HttpResponse::svg(SVG_ROUTE_LEFT)),
            "/assets/route-right.17b0c46a.svg" => Ok(HttpResponse::svg(SVG_ROUTE_RIGHT)),
            "/assets/search.4a30d812.svg" => Ok(HttpResponse::svg(SVG_SEARCH)),
            "/assets/trash-red.65027383.svg" => Ok(HttpResponse::svg(SVG_TRASH_RED)),
            "/assets/trash.d9c6ee55.svg" => Ok(HttpResponse::svg(SVG_TRASH)),
            "/assets/upload.87e6fdfd.svg" => Ok(HttpResponse::svg(SVG_UPLOAD)),
            "/assets/user.5d1f1b14.svg" => Ok(HttpResponse::svg(SVG_USER)),

            "/assets/Inter-italic.var.d1401419.woff2" => Ok(HttpResponse::woff2(FONTS_ITALIC)),
            "/assets/Inter-roman.var.17fe38ab.woff2" => Ok(HttpResponse::woff2(FONTS_ROMAN)),

            _ => Err(req),
        },
        _ => Err(req),
    };

    // Do not log static responses even at TRACE level because by definition
    // static responses are often of little diagnostic value and their large
    // size makes it harder to see other potentially more useful log messages.
    res.map(|mut res| {
        res.do_not_log();
        res
    })
}

pub static INDEX: &[u8] = include_bytes!("../../../ui/index.html");

static FAVICON: &[u8] = include_bytes!("../../../ui/assets/favicon.f84116cb.ico");

static JS_INDEX: &[u8] = include_bytes!("../../../ui/assets/index.86ec8eab.js");

static JS_TRANSLATIONS_GERMAN: &[u8] = include_bytes!("../../../ui/assets/de.0c1879e3.js");
static JS_TRANSLATIONS_ENGLISH: &[u8] = include_bytes!("../../../ui/assets/en.3ab0d1a7.js");
static JS_TRANSLATIONS_SPANISH: &[u8] = include_bytes!("../../../ui/assets/es.ab1a0965.js");
static JS_TRANSLATIONS_FRENCH: &[u8] = include_bytes!("../../../ui/assets/fr.07a7f086.js");
static JS_TRANSLATIONS_GREEK: &[u8] = include_bytes!("../../../ui/assets/gr.a1128018.js");
static JS_TRANSLATIONS_DUTCH: &[u8] = include_bytes!("../../../ui/assets/nl.e60332ba.js");
static JS_TRANSLATIONS_PORTUGUESE: &[u8] = include_bytes!("../../../ui/assets/pt.813d91fd.js");

static CSS: &[u8] = include_bytes!("../../../ui/assets/index.c2dde177.css");

static SVG_CHECK: &[u8] = include_bytes!("../../../ui/assets/check.3e734f78.svg");
static SVG_CHECK_GREEN: &[u8] = include_bytes!("../../../ui/assets/check-green.4525c79c.svg");
static SVG_CLIPBOARD: &[u8] = include_bytes!("../../../ui/assets/clipboard.4659ffea.svg");
static SVG_DOWNLOAD: &[u8] = include_bytes!("../../../ui/assets/download.2dfead4c.svg");
static SVG_ERROR: &[u8] = include_bytes!("../../../ui/assets/error.fd1fc7e1.svg");
static SVG_KRILL_LOGO: &[u8] = include_bytes!("../../../ui/assets/krill_logo_white.05224433.svg");
static SVG_LOGOUT: &[u8] = include_bytes!("../../../ui/assets/logout.c725fd2c.svg");
static SVG_PLUS: &[u8] = include_bytes!("../../../ui/assets/plus.e8f1d182.svg");
static SVG_ROUTE_LEFT: &[u8] = include_bytes!("../../../ui/assets/route-left.c88b44cb.svg");
static SVG_ROUTE_RIGHT: &[u8] = include_bytes!("../../../ui/assets/route-right.17b0c46a.svg");
static SVG_SEARCH: &[u8] = include_bytes!("../../../ui/assets/search.4a30d812.svg");
static SVG_TRASH_RED: &[u8] = include_bytes!("../../../ui/assets/trash-red.65027383.svg");
static SVG_TRASH: &[u8] = include_bytes!("../../../ui/assets/trash.d9c6ee55.svg");
static SVG_UPLOAD: &[u8] = include_bytes!("../../../ui/assets/upload.87e6fdfd.svg");
static SVG_USER: &[u8] = include_bytes!("../../../ui/assets/user.5d1f1b14.svg");

static FONTS_ITALIC: &[u8] = include_bytes!("../../../ui/assets/Inter-italic.var.d1401419.woff2");
static FONTS_ROMAN: &[u8] = include_bytes!("../../../ui/assets/Inter-roman.var.17fe38ab.woff2");
