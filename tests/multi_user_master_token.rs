#[cfg(feature = "ui-tests")]
mod ui;

#[tokio::test]
#[cfg(feature = "ui-tests")]
async fn multi_user_master_token_test() {
    ui::run_krill_ui_test("multi_user_master_token", ui::OpenIDConnectMockMode::OIDCProviderWillNotBeStarted, false).await;
}
