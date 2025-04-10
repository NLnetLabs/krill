//! Build script.
//!
//! This script collects the assets for serving the Krill UI and creates
//! a module for them in `$OUT_DIR/ui_assets.rs`.
use std::{env, fmt, fs, io, process};
use std::path::{PathBuf, Path};

const UI_DIR: &str = "ui";
const INDEX_PATH: &str = "ui/index.html";
const ASSETS_DIR: &str = "ui/assets";
const RS_FILE: &str = "ui_assets.rs";

const TYPES: &[(&str, &str)] = &[
    ("css", "text/css"),
    ("html", "text/html"),
    ("ico", "image/x-icon"),
    ("js", "text/javascript"),
    ("svg", "image/svg+xml"),
    ("woff", "font/woff"),
    ("woff2", "font/woff2"),
];

struct Asset {
    path: PathBuf,
    media_type: &'static str,
    content: Vec<u8>,
}

impl Asset {
    fn load(path: PathBuf, asset: bool) -> Result<Self, String> {
        let path_ext = match path.extension().and_then(|s| s.to_str()) {
            Some(ext) => ext,
            None => {
                return Err(format!(
                    "Asset without extension: '{}'", path.display()
                ))
            }
        };

        let media_type = match TYPES.iter().find_map(|(ext, media_type)| {
            (path_ext == *ext).then_some(*media_type)
        }) {
            Some(media) => media,
            None => {
                return Err(format!(
                    "Asset with unknown extension '{}'", path_ext
                ))
            }
        };

        Ok(Self {
            path: if asset {
                path.strip_prefix(ASSETS_DIR).map_err(|_| {
                    format!("Asset path {} not under {}",
                        path.display(), ASSETS_DIR
                    )
                })?.into()
            }
            else {
                INDEX_PATH.into()
            },
            media_type,
            content: fs::read(&path).map_err(|err| {
                format!(
                    "Failed to read UI asset file {}: {}.",
                    path.display(), err
                )
            })?
        })
    }
}

impl fmt::Display for Asset {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
            "
            Asset {{
                path: r#\"{}\"#,
                media_type: \"{}\",
                content: &{:?},
            }}
            ",
            self.path.display(),
            self.media_type,
            self.content.as_slice(),
        )
    }
}


#[derive(Default)]
struct Assets(Vec<Asset>);

impl Assets {
    fn load_dir(&mut self, path: PathBuf) -> Result<(), String> {
        let dir = fs::read_dir(&path).map_err(|err| {
            format!("Failed to open directory {}: {}", path.display(), err)
        })?;
        for entry in dir {
            let entry = entry.map_err(|err| {
                format!("Failed to read directory {}: {}", path.display(), err)
            })?;
            let path = entry.path();
            if path.is_dir() {
                self.load_dir(path)?;
            }
            else {
                self.0.push(Asset::load(path, true)?)
            }
        }
        Ok(())
    }
}


fn write_mod(
    index: Asset, assets: Assets, dest: &mut impl io::Write
) -> Result<(), io::Error> {
    write!(dest,
        r#"
        pub struct Asset {{
            pub path: &'static str,
            pub media_type: &'static str,
            pub content: &'static [u8],
        }}

        pub static INDEX: Asset = {index};

        pub static ASSETS: &[Asset] = &[
        "#
    )?;
    for item in assets.0 {
        write!(dest, "{},", item)?;
    }
    writeln!(dest, "];")
}


fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap_or_default();
    let target_path = Path::new(&out_dir).join(RS_FILE);
    let mut target = match fs::File::create(&target_path) {
        Ok(target) => io::BufWriter::new(target),
        Err(err) => {
            eprintln!("Failed to open assets module file {}: {}",
                target_path.display(), err
            );
            process::exit(1);
        }
    };

    let index = match Asset::load(INDEX_PATH.into(), false) {
        Ok(index) => index,
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    };

    let mut assets = Assets::default();
    if let Err(err) = assets.load_dir(ASSETS_DIR.into()) {
        eprintln!("{}", err);
        process::exit(1);
    }

    if let Err(err) = write_mod(index, assets, &mut target) {
        eprintln!("Failed to write to assets module file {}: {}",
            target_path.display(), err
        );
        process::exit(1)
    }

    println!("cargo:rerun-if-changed={}", UI_DIR);
}

