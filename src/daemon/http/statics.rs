use hyper::{Method, StatusCode};

use crate::daemon::http::RoutingResult;
use crate::daemon::http::{HttpResponse, Request};
use crate::daemon::config::CONFIG;

#[derive(Serialize)]
struct ConfigJson {
    testbed_enabled: bool
}

pub async fn statics(req: Request) -> RoutingResult {
    match *req.method() {
        Method::GET => match req.path.full() {
            "/" => Ok(HttpResponse(
                hyper::Response::builder()
                    .status(StatusCode::FOUND)
                    .header("location", "/index.html")
                    .body(hyper::Body::empty())
                    .unwrap(),
            )),
            "/index.html" => Ok(HttpResponse::html(INDEX)),
            "/config" if CONFIG.testbed_enabled => Ok(HttpResponse::json(&ConfigJson {
                testbed_enabled: true
            })),
            "/favicon.ico" => Ok(HttpResponse::fav(FAVICON)),
            "/js/app.js" => Ok(HttpResponse::js(APP_JS)),
            "/js/app.js.map" => Ok(HttpResponse::js(APP_JS_MAP)),
            "/css/app.css" => Ok(HttpResponse::css(APP_CSS)),
            "/img/krill_logo_white.svg" => Ok(HttpResponse::svg(IMG_KRILL_LOG)),
            "/img/route_left.svg" => Ok(HttpResponse::svg(IMG_ROUTE_LEFT)),
            "/img/route_right.svg" => Ok(HttpResponse::svg(IMG_ROUTE_RIGHT)),
            "/img/welcome.svg" => Ok(HttpResponse::svg(IMG_ROUTE_WELCOME)),
            "/fonts/element-icons.ttf" => Ok(HttpResponse::woff(FONTS_EL_ICONS_TTF)),
            "/fonts/element-icons.woff" => Ok(HttpResponse::woff(FONTS_EL_ICONS)),
            "/fonts/lato-latin-100.woff" => Ok(HttpResponse::woff(FONTS_LATIN_100)),
            "/fonts/lato-latin-100.woff2" => Ok(HttpResponse::woff2(FONTS_LATIN_100_2)),
            "/fonts/lato-latin-100italic.woff" => Ok(HttpResponse::woff(FONTS_LATIN_100_IT)),
            "/fonts/lato-latin-100italic.woff2" => Ok(HttpResponse::woff2(FONTS_LATIN_100_IT_2)),
            "/fonts/lato-latin-300.woff" => Ok(HttpResponse::woff(FONTS_LATIN_300)),
            "/fonts/lato-latin-300.woff2" => Ok(HttpResponse::woff2(FONTS_LATIN_300_2)),
            "/fonts/lato-latin-300italic.woff" => Ok(HttpResponse::woff(FONTS_LATIN_300_IT)),
            "/fonts/lato-latin-300italic.woff2" => Ok(HttpResponse::woff2(FONTS_LATIN_300_IT_2)),
            "/fonts/lato-latin-400.woff" => Ok(HttpResponse::woff(FONTS_LATIN_400)),
            "/fonts/lato-latin-400.woff2" => Ok(HttpResponse::woff2(FONTS_LATIN_400_2)),
            "/fonts/lato-latin-400italic.woff" => Ok(HttpResponse::woff(FONTS_LATIN_400_IT)),
            "/fonts/lato-latin-400italic.woff2" => Ok(HttpResponse::woff2(FONTS_LATIN_400_IT_2)),
            "/fonts/lato-latin-700.woff" => Ok(HttpResponse::woff(FONTS_LATIN_700)),
            "/fonts/lato-latin-700.woff2" => Ok(HttpResponse::woff2(FONTS_LATIN_700_2)),
            "/fonts/lato-latin-700italic.woff" => Ok(HttpResponse::woff(FONTS_LATIN_700_IT)),
            "/fonts/lato-latin-700italic.woff2" => Ok(HttpResponse::woff2(FONTS_LATIN_700_IT_2)),
            "/fonts/lato-latin-900.woff" => Ok(HttpResponse::woff(FONTS_LATIN_900)),
            "/fonts/lato-latin-900.woff2" => Ok(HttpResponse::woff2(FONTS_LATIN_900_2)),
            "/fonts/lato-latin-900italic.woff" => Ok(HttpResponse::woff(FONTS_LATIN_900_IT)),
            "/fonts/lato-latin-900italic.woff2" => Ok(HttpResponse::woff2(FONTS_LATIN_900_IT_2)),
            "/fonts/source-code-pro-latin-200.woff" => Ok(HttpResponse::woff(FONTS_SOURCE_CODE_200)),
            "/fonts/source-code-pro-latin-200.woff2" => Ok(HttpResponse::woff2(FONTS_SOURCE_CODE_200_2)),
            "/fonts/source-code-pro-latin-300.woff" => Ok(HttpResponse::woff(FONTS_SOURCE_CODE_300)),
            "/fonts/source-code-pro-latin-300.woff2" => Ok(HttpResponse::woff2(FONTS_SOURCE_CODE_300_2)),
            "/fonts/source-code-pro-latin-400.woff" => Ok(HttpResponse::woff(FONTS_SOURCE_CODE_400)),
            "/fonts/source-code-pro-latin-400.woff2" => Ok(HttpResponse::woff2(FONTS_SOURCE_CODE_400_2)),
            "/fonts/source-code-pro-latin-500.woff" => Ok(HttpResponse::woff(FONTS_SOURCE_CODE_500)),
            "/fonts/source-code-pro-latin-500.woff2" => Ok(HttpResponse::woff2(FONTS_SOURCE_CODE_500_2)),
            "/fonts/source-code-pro-latin-600.woff" => Ok(HttpResponse::woff(FONTS_SOURCE_CODE_600)),
            "/fonts/source-code-pro-latin-600.woff2" => Ok(HttpResponse::woff2(FONTS_SOURCE_CODE_600_2)),
            "/fonts/source-code-pro-latin-700.woff" => Ok(HttpResponse::woff(FONTS_SOURCE_CODE_700)),
            "/fonts/source-code-pro-latin-700.woff2" => Ok(HttpResponse::woff2(FONTS_SOURCE_CODE_700_2)),
            "/fonts/source-code-pro-latin-900.woff" => Ok(HttpResponse::woff(FONTS_SOURCE_CODE_900)),
            "/fonts/source-code-pro-latin-900.woff2" => Ok(HttpResponse::woff2(FONTS_SOURCE_CODE_900_2)),
            _ => Err(req),
        },
        _ => Err(req),
    }
}

static INDEX: &[u8] = include_bytes!("../../../lagosta/index.html");
static FAVICON: &[u8] = include_bytes!("../../../lagosta/favicon.ico");

static APP_JS: &[u8] = include_bytes!("../../../lagosta/js/app.js");
static APP_JS_MAP: &[u8] = include_bytes!("../../../lagosta/js/app.js.map");

static APP_CSS: &[u8] = include_bytes!("../../../lagosta/css/app.css");

static IMG_KRILL_LOG: &[u8] = include_bytes!("../../../lagosta/img/krill_logo_white.svg");
static IMG_ROUTE_LEFT: &[u8] = include_bytes!("../../../lagosta/img/route_left.svg");
static IMG_ROUTE_RIGHT: &[u8] = include_bytes!("../../../lagosta/img/route_right.svg");
static IMG_ROUTE_WELCOME: &[u8] = include_bytes!("../../../lagosta/img/welcome.svg");

static FONTS_EL_ICONS_TTF: &[u8] = include_bytes!("../../../lagosta/fonts/element-icons.ttf");
static FONTS_EL_ICONS: &[u8] = include_bytes!("../../../lagosta/fonts/element-icons.woff");
static FONTS_LATIN_100: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-100.woff");
static FONTS_LATIN_100_2: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-100.woff2");
static FONTS_LATIN_100_IT: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-100italic.woff");
static FONTS_LATIN_100_IT_2: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-100italic.woff2");
static FONTS_LATIN_300: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-300.woff");
static FONTS_LATIN_300_2: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-300.woff2");
static FONTS_LATIN_300_IT: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-300italic.woff");
static FONTS_LATIN_300_IT_2: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-300italic.woff2");
static FONTS_LATIN_400: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-400.woff");
static FONTS_LATIN_400_2: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-400.woff2");
static FONTS_LATIN_400_IT: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-400italic.woff");

static FONTS_LATIN_400_IT_2: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-400italic.woff2");
static FONTS_LATIN_700: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-700.woff");
static FONTS_LATIN_700_2: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-700.woff2");
static FONTS_LATIN_700_IT: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-700italic.woff");
static FONTS_LATIN_700_IT_2: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-700italic.woff2");
static FONTS_LATIN_900: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-900.woff");
static FONTS_LATIN_900_2: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-900.woff2");
static FONTS_LATIN_900_IT: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-900italic.woff");
static FONTS_LATIN_900_IT_2: &[u8] = include_bytes!("../../../lagosta/fonts/lato-latin-900italic.woff2");

static FONTS_SOURCE_CODE_200: &[u8] = include_bytes!("../../../lagosta/fonts/source-code-pro-latin-200.woff");
static FONTS_SOURCE_CODE_200_2: &[u8] = include_bytes!("../../../lagosta/fonts/source-code-pro-latin-200.woff2");
static FONTS_SOURCE_CODE_300: &[u8] = include_bytes!("../../../lagosta/fonts/source-code-pro-latin-300.woff");
static FONTS_SOURCE_CODE_300_2: &[u8] = include_bytes!("../../../lagosta/fonts/source-code-pro-latin-300.woff2");
static FONTS_SOURCE_CODE_400: &[u8] = include_bytes!("../../../lagosta/fonts/source-code-pro-latin-400.woff");
static FONTS_SOURCE_CODE_400_2: &[u8] = include_bytes!("../../../lagosta/fonts/source-code-pro-latin-400.woff2");
static FONTS_SOURCE_CODE_500: &[u8] = include_bytes!("../../../lagosta/fonts/source-code-pro-latin-500.woff");
static FONTS_SOURCE_CODE_500_2: &[u8] = include_bytes!("../../../lagosta/fonts/source-code-pro-latin-500.woff2");
static FONTS_SOURCE_CODE_600: &[u8] = include_bytes!("../../../lagosta/fonts/source-code-pro-latin-600.woff");
static FONTS_SOURCE_CODE_600_2: &[u8] = include_bytes!("../../../lagosta/fonts/source-code-pro-latin-600.woff2");
static FONTS_SOURCE_CODE_700: &[u8] = include_bytes!("../../../lagosta/fonts/source-code-pro-latin-700.woff");
static FONTS_SOURCE_CODE_700_2: &[u8] = include_bytes!("../../../lagosta/fonts/source-code-pro-latin-700.woff2");
static FONTS_SOURCE_CODE_900: &[u8] = include_bytes!("../../../lagosta/fonts/source-code-pro-latin-900.woff");
static FONTS_SOURCE_CODE_900_2: &[u8] = include_bytes!("../../../lagosta/fonts/source-code-pro-latin-900.woff2");
