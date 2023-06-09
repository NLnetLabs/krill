use std::path::{Path, PathBuf};
use url::Url;

use crate::commons::{error::Error, KrillResult};

pub fn data_dir_from_storage_uri(storage_uri: &Url) -> Option<PathBuf> {
    if storage_uri.scheme() != "local" {
        None
    } else {
        Some(
            Path::new(&format!(
                "{}{}",
                storage_uri.host_str().unwrap_or(""),
                storage_uri.path()
            ))
            .to_path_buf(),
        )
    }
}

// TODO mark as test only
// #[cfg(test)]
pub fn storage_uri_from_data_dir(data_dir: &Path) -> KrillResult<Url> {
    Url::parse(&format!("local://{}/", data_dir.to_string_lossy())).map_err(|e| Error::custom(e.to_string()))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use url::Url;

    use crate::commons::util::storage::{data_dir_from_storage_uri, storage_uri_from_data_dir};

    #[test]
    fn conversion() {
        assert_eq!(
            data_dir_from_storage_uri(&Url::parse("local:///tmp/test").unwrap()).unwrap(),
            PathBuf::from("/tmp/test")
        );
        assert_eq!(
            data_dir_from_storage_uri(&Url::parse("local://./data").unwrap()).unwrap(),
            PathBuf::from("./data")
        );
        assert_eq!(
            data_dir_from_storage_uri(&Url::parse("local://data").unwrap()).unwrap(),
            PathBuf::from("data")
        );
        assert_eq!(
            data_dir_from_storage_uri(&Url::parse("local://data/test").unwrap()).unwrap(),
            PathBuf::from("data/test")
        );
        assert_eq!(
            storage_uri_from_data_dir(Path::new("./data")).unwrap(),
            Url::parse("local://./data/").unwrap()
        );
        assert_eq!(
            storage_uri_from_data_dir(Path::new("/tmp/data")).unwrap(),
            Url::parse("local:///tmp/data/").unwrap()
        );
    }
}
