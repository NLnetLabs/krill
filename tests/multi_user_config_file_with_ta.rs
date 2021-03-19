#[cfg(all(feature = "ui-tests", feature = "multi-user"))]
mod ui;

#[tokio::test]
#[cfg(all(feature = "ui-tests", feature = "multi-user"))]
async fn multi_user_config_file_with_ta_test() {
    
    use std::{collections::{HashMap, HashSet}, str::FromStr};

    use krill::cli::options::{CaCommand, Command, HistoryOptions};
    use krill::commons::api::Handle;
    use krill::{cli::report::ApiResponse, test::*};

    ui::run_krill_ui_test(
        "multi_user_config_file_with_ta",
        ui::OpenIDConnectMockMode::OIDCProviderWillNotBeStarted,
        true,
    )
    .await;

    // Check the Krill event history after the actions performed against Krill
    // by the Cypress browser driving test script we just executed. Expect at
    // least one action to be attributed to the logged in user who interacted
    // with the CA allocated to them and at least one action with the same CA to
    // be attributed to the internal 'krill' user.
    // TODO: improve this to match the exact sequence of expected actions and
    // attributed actors.
    info!("Verifying that CAs were modified by the expected users according to the history log");

    let mut cas_and_users = HashMap::new();
    cas_and_users.insert("ca_admin", vec!["krill", "user:admin@krill"]);
    cas_and_users.insert("ca_readwrite", vec!["krill", "user:readwrite@krill", "user:joe", "user:sally"]);
    cas_and_users.insert("ca_readonly", vec!["krill", "user:rohelper@krill"]);

    for (ca, expected_users) in cas_and_users {
        let r = krill_admin(Command::CertAuth(CaCommand::ShowHistory(
            Handle::from_str(ca).unwrap(),
            HistoryOptions::default(),
        )))
        .await;

        assert!(
            matches!(r, ApiResponse::CertAuthHistory(_)),
            "Expected a history API response"
        );

        if let ApiResponse::CertAuthHistory(history) = r {
            // each expected user should be present at least once in the history of the CA
            // no other users should be present in the CA history
            let expected_users_set: HashSet<String> = expected_users.iter().map(|u| u.to_string()).collect();
            let found_users_set: HashSet<String> = history.commands().iter().map(|r| r.actor.clone()).collect();

            assert_eq!(
                expected_users_set,
                found_users_set,
                "One or more users in the history of CA '{}' is missing or unexpected",
                ca
            );
        }
    }
}
