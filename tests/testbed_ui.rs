#[cfg(all(feature = "ui-tests", feature = "multi-user"))]
mod ui;

#[tokio::test]
#[cfg(all(feature = "ui-tests", feature = "multi-user"))]
async fn testbed_ui_test() {
    ui::run_krill_ui_test("testbed_ui", ui::OpenIDConnectMockConfig::do_not_start()).await;
}
