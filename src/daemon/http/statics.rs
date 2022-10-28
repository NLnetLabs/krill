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

            "/assets/index.c4081ede.js" => Ok(HttpResponse::js(JS_INDEX)),

            "/assets/en.225f43d6.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_ENGLISH)),
            "/assets/de.d29c510b.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_GERMAN)),
            "/assets/es.7aa2aa17.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_SPANISH)),
            "/assets/fr.6ea7925b.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_FRENCH)),
            "/assets/gr.f1bddb8f.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_GREEK)),
            "/assets/nl.2bcc2306.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_DUTCH)),
            "/assets/pt.e5846b3c.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_PORTUGUESE)),

            "/assets/index.5bd44b44.css" => Ok(HttpResponse::css(CSS)),

            "/assets/check.3e734f78.svg" => Ok(HttpResponse::svg(SVG_CHECK)),
            "/assets/error.fd1fc7e1.svg" => Ok(HttpResponse::svg(SVG_ERROR)),
            "/assets/krill_logo_white.05224433.svg" => Ok(HttpResponse::svg(SVG_KRILL_LOGO)),
            "/assets/logout.c725fd2c.svg" => Ok(HttpResponse::svg(SVG_LOGOUT)),
            "/assets/plus-light.ec5e3c02.svg" => Ok(HttpResponse::svg(SVG_PLUS_LIGHT)),
            "/assets/route-left.c88b44cb.svg" => Ok(HttpResponse::svg(SVG_ROUTE_LEFT)),
            "/assets/route-right.17b0c46a.svg" => Ok(HttpResponse::svg(SVG_ROUTE_RIGHT)),
            "/assets/search.4a30d812.svg" => Ok(HttpResponse::svg(SVG_SEARCH)),
            "/assets/trash-can-light.d9c6ee55.svg" => Ok(HttpResponse::svg(SVG_TRASH_CAN)),
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

static JS_INDEX: &[u8] = include_bytes!("../../../ui/assets/index.c4081ede.js");

static JS_TRANSLATIONS_GERMAN: &[u8] = include_bytes!("../../../ui/assets/de.d29c510b.js");
static JS_TRANSLATIONS_ENGLISH: &[u8] = include_bytes!("../../../ui/assets/en.225f43d6.js");
static JS_TRANSLATIONS_SPANISH: &[u8] = include_bytes!("../../../ui/assets/es.7aa2aa17.js");
static JS_TRANSLATIONS_FRENCH: &[u8] = include_bytes!("../../../ui/assets/fr.6ea7925b.js");
static JS_TRANSLATIONS_GREEK: &[u8] = include_bytes!("../../../ui/assets/gr.f1bddb8f.js");
static JS_TRANSLATIONS_DUTCH: &[u8] = include_bytes!("../../../ui/assets/nl.2bcc2306.js");
static JS_TRANSLATIONS_PORTUGUESE: &[u8] = include_bytes!("../../../ui/assets/pt.e5846b3c.js");

static CSS: &[u8] = include_bytes!("../../../ui/assets/index.5bd44b44.css");

static SVG_CHECK: &[u8] = include_bytes!("../../../ui/assets/check.3e734f78.svg");
static SVG_ERROR: &[u8] = include_bytes!("../../../ui/assets/error.fd1fc7e1.svg");
static SVG_KRILL_LOGO: &[u8] = include_bytes!("../../../ui/assets/krill_logo_white.05224433.svg");
static SVG_LOGOUT: &[u8] = include_bytes!("../../../ui/assets/logout.c725fd2c.svg");
static SVG_PLUS_LIGHT: &[u8] = include_bytes!("../../../ui/assets/plus-light.ec5e3c02.svg");
static SVG_ROUTE_LEFT: &[u8] = include_bytes!("../../../ui/assets/route-left.c88b44cb.svg");
static SVG_ROUTE_RIGHT: &[u8] = include_bytes!("../../../ui/assets/route-right.17b0c46a.svg");
static SVG_SEARCH: &[u8] = include_bytes!("../../../ui/assets/search.4a30d812.svg");
static SVG_TRASH_CAN: &[u8] = include_bytes!("../../../ui/assets/trash-can-light.d9c6ee55.svg");
static SVG_USER: &[u8] = include_bytes!("../../../ui/assets/user.5d1f1b14.svg");

static FONTS_ITALIC: &[u8] = include_bytes!("../../../ui/assets/Inter-italic.var.d1401419.woff2");
static FONTS_ROMAN: &[u8] = include_bytes!("../../../ui/assets/Inter-roman.var.17fe38ab.woff2");
