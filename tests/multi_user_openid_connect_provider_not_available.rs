#[cfg(feature = "ui-tests")]
mod ui;

#[tokio::test]
#[cfg(all(feature = "ui-tests", feature = "multi-user"))]
async fn multi_user_openid_connect_provider_not_available_test() {
    ui::run_krill_ui_test(
        "multi_user_openid_connect_provider_not_available",
        ui::OpenIDConnectMockMode::OIDCProviderWillNotBeStarted,
        false,
    )
    .await
}
