use std::str::FromStr;

use krill::{
    commons::api::{Handle, Token},
    test::{init_ca, start_krill, test_config, tmp_dir},
};

extern crate krill;

#[tokio::test]
#[should_panic]
async fn auth_check() {
    let dir = tmp_dir();
    let mut config = test_config(&dir);
    config.auth_token = Token::from("wrong secret");

    start_krill(Some(config), false).await;

    let ca_handle = Handle::from_str("dummy_ca").unwrap();
    init_ca(&ca_handle).await;
}
