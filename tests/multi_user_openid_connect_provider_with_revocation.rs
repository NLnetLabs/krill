#[cfg(all(feature = "ui-tests", feature = "multi-user"))]
mod ui;

#[tokio::test]
#[cfg(all(feature = "ui-tests", feature = "multi-user"))]
async fn multi_user_openid_connect_provider_with_revocation() {
    use crate::ui::{OpenIDConnectMockConfig, OpenIDConnectMockMode::*};

    ui::run_krill_ui_test(
        "multi_user_openid_connect_provider_with_revocation",
        OpenIDConnectMockConfig::enabled(WithOAuth2Revocation),
    )
    .await
}
