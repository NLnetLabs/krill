#[cfg(all(feature = "ui-tests", feature = "multi-user"))]
mod ui;

#[tokio::test]
#[cfg(all(feature = "ui-tests", feature = "multi-user"))]
async fn multi_user_openid_connect_test() {
    ui::run_krill_ui_test(
        "multi_user_openid_connect",
        ui::OpenIDConnectMockMode::OIDCProviderWithRPInitiatedLogout,
        false,
    )
    .await
}
