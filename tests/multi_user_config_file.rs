mod ui;

#[test]
#[cfg_attr(not(feature = "ui-tests"), ignore)]
fn multi_user_config_file_test() -> Result<(), Box<dyn std::error::Error>> {
    ui::run_krill_ui_test("multi_user_config_file", false)
}