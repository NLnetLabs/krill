#[cfg(feature = "ui-tests")]
mod ui;

#[tokio::test]
#[cfg(feature = "ui-tests")]
async fn multi_user_admin_token_test() {
    ui::run_krill_ui_test("multi_user_admin_token", ui::OpenIDConnectMockConfig::do_not_start()).await;
}
