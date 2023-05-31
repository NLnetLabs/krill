use hyper::{Method, StatusCode};

use crate::daemon::http::RoutingResult;
use crate::daemon::http::{HttpResponse, Request};

pub async fn statics(req: Request) -> RoutingResult {
    let res = match *req.method() {
        Method::GET => match req.path.full() {
            "/" => Ok(HttpResponse::new(
                hyper::Response::builder()
                    .status(StatusCode::FOUND)
                    .header("location", "/ui")
                    .body(hyper::Body::empty())
                    .unwrap(),
            )),
            "/ui" => Ok(HttpResponse::html(INDEX)),

            "/assets/favicon-f84116cb.ico" => Ok(HttpResponse::fav(FAVICON)),

            "/assets/index-638aa63a.js" => Ok(HttpResponse::js(JS_INDEX)),

            "/assets/en-6862b1fd.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_ENGLISH)),
            "/assets/de-a07fd626.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_GERMAN)),
            "/assets/es-398b7024.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_SPANISH)),
            "/assets/fr-00def8c1.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_FRENCH)),
            "/assets/gr-094d4ec7.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_GREEK)),
            "/assets/nl-ac928f6f.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_DUTCH)),
            "/assets/pt-108a6a72.js" => Ok(HttpResponse::js(JS_TRANSLATIONS_PORTUGUESE)),

            "/assets/index-52409a7e.css" => Ok(HttpResponse::css(CSS)),

            "/assets/check-3e734f78.svg" => Ok(HttpResponse::svg(SVG_CHECK)),
            "/assets/check-green-4525c79c.svg" => Ok(HttpResponse::svg(SVG_CHECK_GREEN)),
            "/assets/clipboard-4659ffea.svg" => Ok(HttpResponse::svg(SVG_CLIPBOARD)),
            "/assets/download-2dfead4c.svg" => Ok(HttpResponse::svg(SVG_DOWNLOAD)),
            "/assets/edit-776bf3c3.svg" => Ok(HttpResponse::svg(SVG_EDIT)),
            "/assets/error-fd1fc7e1.svg" => Ok(HttpResponse::svg(SVG_ERROR)),
            "/assets/krill_logo_white-05224433.svg" => Ok(HttpResponse::svg(SVG_KRILL_LOGO)),
            "/assets/logout-c725fd2c.svg" => Ok(HttpResponse::svg(SVG_LOGOUT)),
            "/assets/plus-e8f1d182.svg" => Ok(HttpResponse::svg(SVG_PLUS)),
            "/assets/route-left-c88b44cb.svg" => Ok(HttpResponse::svg(SVG_ROUTE_LEFT)),
            "/assets/route-right-17b0c46a.svg" => Ok(HttpResponse::svg(SVG_ROUTE_RIGHT)),
            "/assets/search-4a30d812.svg" => Ok(HttpResponse::svg(SVG_SEARCH)),
            "/assets/trash-red-65027383.svg" => Ok(HttpResponse::svg(SVG_TRASH_RED)),
            "/assets/trash-d9c6ee55.svg" => Ok(HttpResponse::svg(SVG_TRASH)),
            "/assets/upload-87e6fdfd.svg" => Ok(HttpResponse::svg(SVG_UPLOAD)),
            "/assets/user-5d1f1b14.svg" => Ok(HttpResponse::svg(SVG_USER)),
            "/assets/welcome-9fadc7f2.svg" => Ok(HttpResponse::svg(SVG_WELCOME)),

            "/assets/Inter-italic.var-d1401419.woff2" => Ok(HttpResponse::woff2(FONTS_ITALIC)),
            "/assets/Inter-roman.var-17fe38ab.woff2" => Ok(HttpResponse::woff2(FONTS_ROMAN)),

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

static FAVICON: &[u8] = include_bytes!("../../../ui/assets/favicon-f84116cb.ico");

static JS_INDEX: &[u8] = include_bytes!("../../../ui/assets/index-638aa63a.js");

static JS_TRANSLATIONS_GERMAN: &[u8] = include_bytes!("../../../ui/assets/de-a07fd626.js");
static JS_TRANSLATIONS_ENGLISH: &[u8] = include_bytes!("../../../ui/assets/en-6862b1fd.js");
static JS_TRANSLATIONS_SPANISH: &[u8] = include_bytes!("../../../ui/assets/es-398b7024.js");
static JS_TRANSLATIONS_FRENCH: &[u8] = include_bytes!("../../../ui/assets/fr-00def8c1.js");
static JS_TRANSLATIONS_GREEK: &[u8] = include_bytes!("../../../ui/assets/gr-094d4ec7.js");
static JS_TRANSLATIONS_DUTCH: &[u8] = include_bytes!("../../../ui/assets/nl-ac928f6f.js");
static JS_TRANSLATIONS_PORTUGUESE: &[u8] = include_bytes!("../../../ui/assets/pt-108a6a72.js");

static CSS: &[u8] = include_bytes!("../../../ui/assets/index-52409a7e.css");

static SVG_CHECK: &[u8] = include_bytes!("../../../ui/assets/check-3e734f78.svg");
static SVG_CHECK_GREEN: &[u8] = include_bytes!("../../../ui/assets/check-green-4525c79c.svg");
static SVG_CLIPBOARD: &[u8] = include_bytes!("../../../ui/assets/clipboard-4659ffea.svg");
static SVG_DOWNLOAD: &[u8] = include_bytes!("../../../ui/assets/download-2dfead4c.svg");
static SVG_EDIT: &[u8] = include_bytes!("../../../ui/assets/edit-776bf3c3.svg");
static SVG_ERROR: &[u8] = include_bytes!("../../../ui/assets/error-fd1fc7e1.svg");
static SVG_KRILL_LOGO: &[u8] = include_bytes!("../../../ui/assets/krill_logo_white-05224433.svg");
static SVG_LOGOUT: &[u8] = include_bytes!("../../../ui/assets/logout-c725fd2c.svg");
static SVG_PLUS: &[u8] = include_bytes!("../../../ui/assets/plus-e8f1d182.svg");
static SVG_ROUTE_LEFT: &[u8] = include_bytes!("../../../ui/assets/route-left-c88b44cb.svg");
static SVG_ROUTE_RIGHT: &[u8] = include_bytes!("../../../ui/assets/route-right-17b0c46a.svg");
static SVG_SEARCH: &[u8] = include_bytes!("../../../ui/assets/search-4a30d812.svg");
static SVG_TRASH_RED: &[u8] = include_bytes!("../../../ui/assets/trash-red-65027383.svg");
static SVG_TRASH: &[u8] = include_bytes!("../../../ui/assets/trash-d9c6ee55.svg");
static SVG_UPLOAD: &[u8] = include_bytes!("../../../ui/assets/upload-87e6fdfd.svg");
static SVG_USER: &[u8] = include_bytes!("../../../ui/assets/user-5d1f1b14.svg");
static SVG_WELCOME: &[u8] = include_bytes!("../../../ui/assets/welcome-9fadc7f2.svg");

static FONTS_ITALIC: &[u8] = include_bytes!("../../../ui/assets/Inter-italic.var-d1401419.woff2");
static FONTS_ROMAN: &[u8] = include_bytes!("../../../ui/assets/Inter-roman.var-17fe38ab.woff2");
