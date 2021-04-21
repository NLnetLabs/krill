#[cfg(feature = "ui-tests")]
mod ui;

#[tokio::test]
#[cfg(all(feature = "ui-tests", feature = "multi-user"))]
async fn multi_user_team_based_access_test() {
    ui::run_krill_ui_test(
        "multi_user_team_based_access",
        ui::OpenIDConnectMockConfig::do_not_start()
    )
    .await
}
