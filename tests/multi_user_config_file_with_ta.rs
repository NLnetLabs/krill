#![recursion_limit = "155"]

use std::{collections::HashMap, str::FromStr};

use krill::{cli::report::ApiResponse, test::*};
use krill::cli::options::{Command, CaCommand, HistoryOptions};
use krill::commons::api::Handle;

#[cfg(feature = "ui-tests")]
mod ui;

#[tokio::test]
#[cfg(all(feature = "ui-tests", feature = "multi-user"))]
async fn multi_user_config_file_with_ta_test() {
    std::env::set_var("KRILL_TEST", "true");

    ui::run_krill_ui_test("multi_user_config_file_with_ta", false).await;

    // Check the Krill event history after the actions performed against Krill
    // by the Cypress browser driving test script we just executed. Expect at
    // least one action to be attributed to the logged in user who interacted
    // with the CA allocated to them and at least one action with the same CA to
    // be attributed to the internal 'krill' user.
    // TODO: improve this to match the exact sequence of expected actions and
    // attributed actors.
    let mut cas_and_users = HashMap::new();
    cas_and_users.insert("ca_admin",     "admin@krill");
    cas_and_users.insert("ca_readwrite", "readwrite@krill");
    cas_and_users.insert("ca_readonly",  "rohelper@krill");

    for (ca, user) in cas_and_users {
        let r = krill_admin(
            Command::CertAuth(
                CaCommand::ShowHistory(
                    Handle::from_str(ca).unwrap(),
                    HistoryOptions::default()))).await;

        assert!(matches!(r, ApiResponse::CertAuthHistory(_)), "Expected a history API response");

        if let ApiResponse::CertAuthHistory(history) = r {
            let mut krill_count = 0;
            let mut user_count = 0;
            for cmd in history.commands() {
                let expected_user = format!("user:{}", user);
                match &cmd.actor {
                    s if s == "krill"        => krill_count += 1,
                    s if s == &expected_user => user_count += 1,
                    _ => assert!(false, format!("Unexpected actor {} in history for CA '{}'", &cmd.actor, ca)),
                }
            }
            assert!(krill_count > 0, format!("Missing history actions by user krill for CA '{}'", ca));
            assert!(user_count > 0, format!("Missing history actions by user '{}' for CA '{}'", user, ca));
        }
    }
}