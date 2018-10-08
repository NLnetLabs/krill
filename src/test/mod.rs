#[cfg(test)]
pub fn test_with_tmp_dir<F>(f: F) where F: FnOnce(String) -> () {
    use std::fs;
    use std::path::PathBuf;
    use rand::{thread_rng, Rng};

    let mut rng = thread_rng();
    let r: u32 = rng.gen();

    let dir = format!("work/{}", r);

    let full_path = PathBuf::from(&dir);
    fs::create_dir(&full_path).unwrap();

    f(dir);

    fs::remove_dir_all(&full_path).unwrap();
}