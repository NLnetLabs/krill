extern crate krill_client;
extern crate krill_commons;
extern crate krill_daemon;
extern crate krill_pubc;

use std::collections::HashSet;
use std::path::PathBuf;
use krill_client::KrillClient;
use krill_client::options::{
    AddPublisher,
    AddRfc8181Client,
    Command,
    Options,
    PublishersCommand,
    Rfc8181Command,
};
use krill_client::report::ReportFormat;
use krill_commons::api::admin::{
    Handle,
    Token
};
use krill_commons::api::publication::ListReply;
use krill_commons::remote::rfc8183::RepositoryResponse;
use krill_commons::util::file::CurrentFile;
use krill_commons::util::file;
use krill_commons::util::httpclient;
use krill_commons::util::test;
use krill_pubc::{ApiResponse, Format};
use krill_pubc::apiclient;
use krill_pubc::cmsclient;
use krill_pubc::cmsclient::PubClient;

fn list(server_uri: &str, handle: &str, token: &str) -> apiclient::Options {
    let conn = apiclient::Connection::build(server_uri, handle, token).unwrap();
    let cmd = apiclient::Command::List;
    let fmt = Format::Json;

    apiclient::Options::new(conn, cmd, fmt)
}

fn sync(
    server_uri: &str,
    handle: &str,
    token: &str,
    syncdir: &PathBuf,
    base_uri: &str
) -> apiclient::Options {
    let conn = apiclient::Connection::build(server_uri, handle, token).unwrap();
    let cmd = apiclient::Command::sync(syncdir.to_str().unwrap(), base_uri).unwrap();
    let fmt = Format::Json;

    apiclient::Options::new(conn, cmd, fmt)
}

fn execute_krillc_command(command: Command) {
    let krillc_opts = Options::new(
        test::https("https://localhost:3000/"),
        "secret",
        ReportFormat::Default,
        command
    );
    match KrillClient::test(krillc_opts) {
        Ok(_res) => {}, // ok
        Err(e) => {
            panic!("{}", e)
        }
    }
}

fn add_publisher(handle: &str, base_uri: &str, token: &str) {
    let command = Command::Publishers(PublishersCommand::Add(
        AddPublisher {
            handle:   Handle::from(handle),
            base_uri: test::rsync(base_uri),
            token:    Token::from(token)
        }
    ));
    execute_krillc_command(command);
}

fn remove_publisher(handle: &str) {
    let command = Command::Publishers(
        PublishersCommand::Deactivate(handle.to_string())
    );

    execute_krillc_command(command);
}

fn rfc8181_client_init(handle: &str, state_dir: &PathBuf) {
    let command = cmsclient::Command::init(handle);
    rfc8181_client_process_command(command, &state_dir);
}

fn rfc8181_client_add(state_dir: &PathBuf)  {
    let mut pr_path = state_dir.clone();
    pr_path.push("request.xml");

    let command = cmsclient::Command::publisher_request(pr_path.clone());
    rfc8181_client_process_command(command, &state_dir);

    let command = Command::Rfc8181(
        Rfc8181Command::Add(
            AddRfc8181Client { xml: pr_path }
        )
    );

    execute_krillc_command(command);
}

#[allow(dead_code)]
fn rfc8181_client_process_response(res_path: &PathBuf, state_dir: &PathBuf) {
    let command = cmsclient::Command::repository_response(res_path.clone());
    rfc8181_client_process_command(command, &state_dir);
}

#[allow(dead_code)]
fn rfc8181_client_list(state_dir: &PathBuf) -> ListReply {
    let command = cmsclient::Command::list();
    let api_response = rfc8181_client_process_command(command, &state_dir);
    match api_response {
        ApiResponse::Success => panic!("Expected list"),
        ApiResponse::List(list) => list
    }
}

#[allow(dead_code)]
fn rfc8181_client_sync(state_dir: &PathBuf, sync_dir: &PathBuf) {
    let command = cmsclient::Command::sync(sync_dir.clone());
    rfc8181_client_process_command(command, state_dir);
}

#[allow(dead_code)]
fn rfc8181_client_process_command(command: cmsclient::Command, state_dir: &PathBuf) -> ApiResponse {
    let options = cmsclient::Options::new(state_dir.clone(), command, Format::None);
    PubClient::execute(options).unwrap()
}

#[allow(dead_code)]
fn get_repository_response(handle: &str) -> RepositoryResponse {
    let uri = format!("https://localhost:3000/api/v1/rfc8181/{}/response.xml", handle);
    let content_type = "application/xml";
    let token = Token::from("secret");

    let xml = httpclient::get_text(
        &uri, content_type, Some(&token)
    ).unwrap();

    RepositoryResponse::validate(xml.as_bytes()).unwrap()
}

#[test]
fn client_publish() {
    krill_daemon::test::test_with_krill_server(|d| {

        let server_uri = "https://localhost:3000/";
        let handle = "alice";
        let token = "secret";
        let base_rsync_uri_alice = "rsync://localhost/repo/alice/";
        let base_rsync_uri_bob = "rsync://localhost/repo/bob/";

        // Add client "alice"
        add_publisher(handle, base_rsync_uri_alice, token);

        // Calls to api should require the correct token
        {
            let res = apiclient::execute(list(
                server_uri,
                handle,
                "wrong token"
            ));

            match res {
                Err(apiclient::Error::HttpClientError
                    (httpclient::Error::Forbidden)) => {},
                Err(e) => panic!("Expected forbidden, got: {}", e),
                _ => panic!("Expected forbidden")
            }
        }

        // List files at server, expect no files
        {
            let list = apiclient::execute(list(
                server_uri,
                handle,
                token
            )).unwrap();

            match list {
                ApiResponse::List(list) => {
                    assert_eq!(0, list.elements().len());
                },
                _ => panic!("Expected list")
            }
        }


        // Create files on disk to sync
        let sync_dir = test::sub_dir(&d);
        let file_a = CurrentFile::new(
            test::rsync("rsync://localhost/repo/alice/a.txt"),
            &test::as_bytes("a")
        );
        let file_b = CurrentFile::new(
            test::rsync("rsync://localhost/repo/alice/b.txt"),
            &test::as_bytes("b")
        );
        let file_c = CurrentFile::new(
            test::rsync("rsync://localhost/repo/alice/c.txt"),
            &test::as_bytes("c")
        );

        file::save_in_dir(&file_a.to_bytes(), &sync_dir, "a.txt").unwrap();
        file::save_in_dir(&file_b.to_bytes(), &sync_dir, "b.txt").unwrap();
        file::save_in_dir(&file_c.to_bytes(), &sync_dir, "c.txt").unwrap();


        // Must refuse syncing files outside of publisher base dir
        {
            let api_res = apiclient::execute(sync(
                server_uri,
                handle,
                token,
                &sync_dir,
                base_rsync_uri_bob
            ));

            assert!(api_res.is_err())
        }


        // Sync files
        {
            let api_res = apiclient::execute(sync(
                server_uri,
                handle,
                token,
                &sync_dir,
                base_rsync_uri_alice
            )).unwrap();

            assert_eq!(ApiResponse::Success, api_res);
        }

        // We should now see these files when we list
        {
            let list = apiclient::execute(list(
                server_uri,
                handle,
                token
            )).unwrap();

            match list {
                ApiResponse::List(list) => {
                    assert_eq!(3, list.elements().len());

                    let returned_set: HashSet<_>  = list.elements().iter().collect();

                    let list_el_a = file_a.into_list_element();
                    let list_el_b = file_b.into_list_element();
                    let list_el_c = file_c.clone().into_list_element();

                    let expected_elements = vec![
                        &list_el_a,
                        &list_el_b,
                        &list_el_c
                    ];
                    let expected_set: HashSet<_> = expected_elements.into_iter().collect();
                    assert_eq!(expected_set, returned_set);
                },
                _ => panic!("Expected list")
            }
        }

        // XXX TODO We should also see these files in RRDP


        // Now we should be able to delete it all again
        file::delete_in_dir(&sync_dir, "a.txt").unwrap();
        file::delete_in_dir(&sync_dir, "b.txt").unwrap();

        // Sync files
        {
            let api_res = apiclient::execute(sync(
                server_uri,
                handle,
                token,
                &sync_dir,
                base_rsync_uri_alice
            )).unwrap();

            assert_eq!(ApiResponse::Success, api_res);
        }

        // List files at server, expect 1 file (c.txt)
        {
            let list = apiclient::execute(list(
                server_uri,
                handle,
                token
            )).unwrap();

            match list {
                ApiResponse::List(list) => {
                    assert_eq!(1, list.elements().len());

                    let returned_set: HashSet<_>  = list.elements().iter().collect();

                    let list_el_c = file_c.into_list_element();

                    let expected_elements = vec![&list_el_c];
                    let expected_set: HashSet<_> = expected_elements.into_iter().collect();
                    assert_eq!(expected_set, returned_set);
                },
                _ => panic!("Expected list")
            }
        }

        // Remove alice
        remove_publisher(handle);

        // XXX TODO Must remove files when removing publisher
        // Expect that c.txt is removed when looking at latest snapshot.
        file::delete_in_dir(&sync_dir, "c.txt").unwrap();

        // Now test with CMS proxy

        let handle = "carol";
        let token = "secret";
        let base_rsync_uri = "rsync://localhost/repo/carol/";

        // Add client "carol"
        add_publisher(handle, base_rsync_uri, token);

        let state_dir = test::sub_dir(&d);

        // Add RFC8181 client for alice
        rfc8181_client_init(handle, &state_dir);

        rfc8181_client_add(&state_dir);

        // Get the server response.xml and add it to the client
        let response = get_repository_response(handle);
        let mut response_path = state_dir.clone();
        response_path.push("response.xml");
        response.save(&response_path).unwrap();

        rfc8181_client_process_response(&response_path, &state_dir);

        // List the files
        let list = rfc8181_client_list(&state_dir);
        assert_eq!(0, list.elements().len());

        // Create files on disk to sync
        let sync_dir = test::sub_dir(&d);
        let file_a = CurrentFile::new(
            test::rsync("rsync://localhost/repo/alice/a.txt"),
            &test::as_bytes("a")
        );
        let file_b = CurrentFile::new(
            test::rsync("rsync://localhost/repo/alice/b.txt"),
            &test::as_bytes("b")
        );
        let file_c = CurrentFile::new(
            test::rsync("rsync://localhost/repo/alice/c.txt"),
            &test::as_bytes("c")
        );

        file::save_in_dir(&file_a.to_bytes(), &sync_dir, "a.txt").unwrap();
        file::save_in_dir(&file_b.to_bytes(), &sync_dir, "b.txt").unwrap();
        file::save_in_dir(&file_c.to_bytes(), &sync_dir, "c.txt").unwrap();

        // Sync
        rfc8181_client_sync(&state_dir, &sync_dir);

        // List the files
        let list = rfc8181_client_list(&state_dir);
        assert_eq!(3, list.elements().len());
    });

}