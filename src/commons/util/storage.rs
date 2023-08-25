use std::path::Path;
use url::Url;

use crate::commons::{error::Error, KrillResult};

// TODO mark as test only
// #[cfg(test)]
pub fn storage_uri_from_data_dir(data_dir: &Path) -> KrillResult<Url> {
    Url::parse(&format!("local://{}/", data_dir.to_string_lossy())).map_err(|e| Error::custom(e.to_string()))
}
