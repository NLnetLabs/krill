use actix_service::NewService;
use actix_web::dev::{MessageBody, ServiceRequest, ServiceResponse};
use actix_web::{web, App, Error, HttpResponse};

/// This trait allows for adding static content.
/// Using a trait here so that it can be used fluidly in the
/// building of the 'App'.
pub trait WithStaticContent {
    /// Add a single static resource.
    fn add_static(self, static_content: &'static StaticContent) -> Self;

    /// Add all static resources defined in this module.
    fn add_statics(self) -> Self;
}

/// Implementation for the App type that is returned when App::new()
/// is used.
impl<T, B> WithStaticContent for App<T, B>
where
    B: MessageBody,
    T: NewService<
        Config = (),
        Request = ServiceRequest,
        Response = ServiceResponse<B>,
        Error = Error,
        InitError = (),
    >,
{
    fn add_static(self, static_content: &'static StaticContent) -> Self {
        self.route(
            static_content.web_path,
            web::get().to(move || {
                HttpResponse::Ok()
                    .content_type(static_content.ctype)
                    .header("Cache-Control", "max-age: 86400")
                    .body(static_content.content)
            }),
        )
    }

    fn add_statics(self) -> Self {
        self.add_static(&NOT_FOUND)
            .add_static(&INDEX)
            .add_static(&FAVICON)
            .add_static(&APP_JS)
            .add_static(&APP_JS_MAP)
            .add_static(&APP_CSS)
            .add_static(&IMG_KRILL_LOG)
            .add_static(&IMG_ROUTE_LEFT)
            .add_static(&IMG_ROUTE_RIGHT)
            .add_static(&FONTS_EL_ICONS)
            .add_static(&FONTS_LATIN_100)
            .add_static(&FONTS_LATIN_100_2)
            .add_static(&FONTS_LATIN_300)
            .add_static(&FONTS_LATIN_300_2)
            .add_static(&FONTS_LATIN_400)
            .add_static(&FONTS_LATIN_400_2)
            .add_static(&FONTS_LATIN_700)
            .add_static(&FONTS_LATIN_700_2)
            .add_static(&FONTS_LATIN_900)
            .add_static(&FONTS_LATIN_900_2)
            .add_static(&FONTS_LATIN_100_IT)
            .add_static(&FONTS_LATIN_100_IT_2)
            .add_static(&FONTS_LATIN_300_IT)
            .add_static(&FONTS_LATIN_300_IT_2)
            .add_static(&FONTS_LATIN_400_IT)
            .add_static(&FONTS_LATIN_400_IT_2)
            .add_static(&FONTS_LATIN_700_IT)
            .add_static(&FONTS_LATIN_700_IT_2)
            .add_static(&FONTS_LATIN_900_IT)
            .add_static(&FONTS_SOURCE_CODE_200)
            .add_static(&FONTS_SOURCE_CODE_200_2)
            .add_static(&FONTS_SOURCE_CODE_300)
            .add_static(&FONTS_SOURCE_CODE_300_2)
            .add_static(&FONTS_SOURCE_CODE_400)
            .add_static(&FONTS_SOURCE_CODE_400_2)
            .add_static(&FONTS_SOURCE_CODE_700)
            .add_static(&FONTS_SOURCE_CODE_700_2)
            .add_static(&FONTS_SOURCE_CODE_900)
            .add_static(&FONTS_SOURCE_CODE_900_2)
    }
}

//------------ StaticContent -------------------------------------------------

pub struct StaticContent {
    pub web_path: &'static str,
    pub content: &'static [u8],
    pub ctype: &'static str,
}

//------------ Definition of Statics -----------------------------------------

static HTML: &'static str = "text/html";
static FAV: &'static str = "image/x-icon";
static JS: &'static str = "application/javascript";
static CSS: &'static str = "text/css";
static SVG: &'static str = "image/svg+xml";
static WOFF: &'static str = "font/woff";
static WOFF2: &'static str = "font/woff2";

static NOT_FOUND: StaticContent = StaticContent {
    web_path: "/ui/404.html",
    content: include_bytes!("../../ui/dist/404.html"),
    ctype: HTML,
};
static INDEX: StaticContent = StaticContent {
    web_path: "/ui/index.html",
    content: include_bytes!("../../ui/dist/index.html"),
    ctype: HTML,
};
static FAVICON: StaticContent = StaticContent {
    web_path: "/ui/favicon.ico",
    content: include_bytes!("../../ui/dist/favicon.ico"),
    ctype: FAV,
};
static APP_JS: StaticContent = StaticContent {
    web_path: "/ui/js/app.js",
    content: include_bytes!("../../ui/dist/js/app.js"),
    ctype: JS,
};
static APP_JS_MAP: StaticContent = StaticContent {
    web_path: "/ui/js/app.js.map",
    content: include_bytes!("../../ui/dist/js/app.js.map"),
    ctype: JS,
};
static APP_CSS: StaticContent = StaticContent {
    web_path: "/ui/css/app.css",
    content: include_bytes!("../../ui/dist/css/app.css"),
    ctype: CSS,
};
static IMG_KRILL_LOG: StaticContent = StaticContent {
    web_path: "/ui/img/krill_logo_white.svg",
    content: include_bytes!("../../ui/dist/img/krill_logo_white.svg"),
    ctype: SVG,
};
static IMG_ROUTE_LEFT: StaticContent = StaticContent {
    web_path: "/ui/img/route_left.svg",
    content: include_bytes!("../../ui/dist/img/route_left.svg"),
    ctype: SVG,
};
static IMG_ROUTE_RIGHT: StaticContent = StaticContent {
    web_path: "/ui/img/route_right.svg",
    content: include_bytes!("../../ui/dist/img/route_right.svg"),
    ctype: SVG,
};
static FONTS_EL_ICONS: StaticContent = StaticContent {
    web_path: "/ui/fonts/element-icons.woff",
    content: include_bytes!("../../ui/dist/fonts/element-icons.woff"),
    ctype: WOFF,
};
static FONTS_LATIN_100: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-100.woff",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-100.woff"),
    ctype: WOFF,
};
static FONTS_LATIN_100_2: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-100.woff2",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-100.woff2"),
    ctype: WOFF2,
};
static FONTS_LATIN_300: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-300.woff",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-300.woff"),
    ctype: WOFF,
};
static FONTS_LATIN_300_2: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-300.woff2",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-300.woff2"),
    ctype: WOFF2,
};
static FONTS_LATIN_400: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-400.woff",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-400.woff"),
    ctype: WOFF,
};
static FONTS_LATIN_400_2: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-400.woff2",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-400.woff2"),
    ctype: WOFF2,
};
static FONTS_LATIN_700: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-700.woff",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-700.woff"),
    ctype: WOFF,
};
static FONTS_LATIN_700_2: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-700.woff2",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-700.woff2"),
    ctype: WOFF2,
};
static FONTS_LATIN_900: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-900.woff",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-900.woff"),
    ctype: WOFF,
};
static FONTS_LATIN_900_2: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-900.woff2",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-900.woff2"),
    ctype: WOFF2,
};
static FONTS_LATIN_100_IT: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-100italic.woff",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-100italic.woff"),
    ctype: WOFF,
};
static FONTS_LATIN_100_IT_2: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-100italic.woff2",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-100italic.woff2"),
    ctype: WOFF2,
};
static FONTS_LATIN_300_IT: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-300italic.woff",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-300italic.woff"),
    ctype: WOFF,
};
static FONTS_LATIN_300_IT_2: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-300italic.woff2",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-300italic.woff2"),
    ctype: WOFF2,
};
static FONTS_LATIN_400_IT: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-400italic.woff",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-400italic.woff"),
    ctype: WOFF,
};
static FONTS_LATIN_400_IT_2: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-400italic.woff2",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-400italic.woff2"),
    ctype: WOFF2,
};
static FONTS_LATIN_700_IT: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-700italic.woff",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-700italic.woff"),
    ctype: WOFF,
};
static FONTS_LATIN_700_IT_2: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-700italic.woff2",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-700italic.woff2"),
    ctype: WOFF2,
};
static FONTS_LATIN_900_IT: StaticContent = StaticContent {
    web_path: "/ui/fonts/lato-latin-900italic.woff",
    content: include_bytes!("../../ui/dist/fonts/lato-latin-900italic.woff"),
    ctype: WOFF,
};
static FONTS_SOURCE_CODE_200: StaticContent = StaticContent {
    web_path: "/ui/fonts/source-code-pro-latin-200.woff",
    content: include_bytes!("../../ui/dist/fonts/source-code-pro-latin-200.woff"),
    ctype: WOFF,
};
static FONTS_SOURCE_CODE_200_2: StaticContent = StaticContent {
    web_path: "/ui/fonts/source-code-pro-latin-200.woff2",
    content: include_bytes!("../../ui/dist/fonts/source-code-pro-latin-200.woff2"),
    ctype: WOFF2,
};
static FONTS_SOURCE_CODE_300: StaticContent = StaticContent {
    web_path: "/ui/fonts/source-code-pro-latin-300.woff",
    content: include_bytes!("../../ui/dist/fonts/source-code-pro-latin-300.woff"),
    ctype: WOFF,
};
static FONTS_SOURCE_CODE_300_2: StaticContent = StaticContent {
    web_path: "/ui/fonts/source-code-pro-latin-300.woff2",
    content: include_bytes!("../../ui/dist/fonts/source-code-pro-latin-300.woff2"),
    ctype: WOFF2,
};
static FONTS_SOURCE_CODE_400: StaticContent = StaticContent {
    web_path: "/ui/fonts/source-code-pro-latin-400.woff",
    content: include_bytes!("../../ui/dist/fonts/source-code-pro-latin-400.woff"),
    ctype: WOFF,
};
static FONTS_SOURCE_CODE_400_2: StaticContent = StaticContent {
    web_path: "/ui/fonts/source-code-pro-latin-400.woff2",
    content: include_bytes!("../../ui/dist/fonts/source-code-pro-latin-400.woff2"),
    ctype: WOFF2,
};
static FONTS_SOURCE_CODE_700: StaticContent = StaticContent {
    web_path: "/ui/fonts/source-code-pro-latin-700.woff",
    content: include_bytes!("../../ui/dist/fonts/source-code-pro-latin-700.woff"),
    ctype: WOFF,
};
static FONTS_SOURCE_CODE_700_2: StaticContent = StaticContent {
    web_path: "/ui/fonts/source-code-pro-latin-700.woff2",
    content: include_bytes!("../../ui/dist/fonts/source-code-pro-latin-700.woff2"),
    ctype: WOFF2,
};
static FONTS_SOURCE_CODE_900: StaticContent = StaticContent {
    web_path: "/ui/fonts/source-code-pro-latin-900.woff",
    content: include_bytes!("../../ui/dist/fonts/source-code-pro-latin-900.woff"),
    ctype: WOFF,
};
static FONTS_SOURCE_CODE_900_2: StaticContent = StaticContent {
    web_path: "/ui/fonts/source-code-pro-latin-900.woff2",
    content: include_bytes!("../../ui/dist/fonts/source-code-pro-latin-900.woff2"),
    ctype: WOFF2,
};
