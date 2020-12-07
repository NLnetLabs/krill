#![recursion_limit = "155"]

#[cfg(feature = "ui-tests")]
mod ui;

#[ignore = "currently failing so will prevent tarpaulin coverage run finishing"]
#[tokio::test]
#[cfg(all(feature = "ui-tests", feature = "multi-user"))]
async fn multi_user_config_file_with_ta_test() {
    std::env::set_var("KRILL_TEST", "true");
    ui::run_krill_ui_test("multi_user_config_file_with_ta", false).await
}