mod ui;

#[test]
#[cfg_attr(not(feature = "web-ui-tests"), ignore)]
fn multi_user_master_token_test() -> Result<(), Box<dyn std::error::Error>> {
    ui::run_krill_ui_test("multi_user_master_token")
}