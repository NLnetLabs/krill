#[cfg(feature = "ui-tests")]
mod ui;

#[tokio::test]
#[cfg(all(feature = "ui-tests", feature = "multi-user"))]
async fn multi_user_openid_connect_provider_with_revocation() {
    ui::run_krill_ui_test(
        "multi_user_openid_connect_provider_with_fallback_logout",
        ui::OpenIDConnectMockMode::OIDCProviderWithNoLogoutEndpoints,
        false,
    )
    .await
}