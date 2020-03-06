use bytes::Bytes;
use rand::{thread_rng, Rng};
use rpki::uri;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

/// This method sets up a test directory with a random name (a number)
/// under 'work', relative to where cargo is running. It then runs the
/// test provided in the closure, and finally it cleans up the test
/// directory.
///
/// Note that if your test fails the directory is not cleaned up.
pub fn test_under_tmp<F>(op: F)
where
    F: FnOnce(PathBuf) -> (),
{
    let dir = sub_dir(&PathBuf::from("work"));
    let path = PathBuf::from(&dir);

    op(dir);

    let _result = fs::remove_dir_all(path);
}

/// This method sets up a random subdirectory and returns it. It is
/// assumed that the caller will clean this directory themselves.
pub fn sub_dir(base_dir: &PathBuf) -> PathBuf {
    let mut rng = thread_rng();
    let rnd: u32 = rng.gen();

    let mut dir = base_dir.clone();
    dir.push(PathBuf::from(format!("{}", rnd)));

    let full_path = PathBuf::from(&dir);
    fs::create_dir_all(&full_path).unwrap();

    full_path
}

pub fn rsync(s: &str) -> uri::Rsync {
    uri::Rsync::from_str(s).unwrap()
}

pub fn https(s: &str) -> uri::Https {
    uri::Https::from_str(s).unwrap()
}

pub fn as_bytes(s: &str) -> Bytes {
    Bytes::copy_from_slice(s.as_bytes())
}

pub fn save_file(base_dir: &PathBuf, file_name: &str, content: &[u8]) {
    let mut full_name = base_dir.clone();
    full_name.push(PathBuf::from(file_name));
    let mut f = File::create(full_name).unwrap();
    f.write_all(content).unwrap();
}
