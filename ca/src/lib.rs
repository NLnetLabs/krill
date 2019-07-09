extern crate base64;
extern crate bytes;
extern crate chrono;
extern crate core;
#[macro_use] extern crate derive_more;
extern crate hex;
#[macro_use] extern crate log;
extern crate rand;
#[macro_use] extern crate serde;
extern crate serde_json;

extern crate bcder;
extern crate rpki;
extern crate krill_commons;

mod ca;
pub use ca::ta_handle;

mod caserver;
pub use self::caserver::CaServer;
pub use self::caserver::Error as CaServerError;

mod signing;
pub use self::signing::CaSigner;
pub use self::signing::CaSignSupport;

mod publishing;
pub use self::publishing::PubClients;
pub use self::publishing::Error as PubClientError;


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, RwLock};

    use rpki::crypto::signer::Signer;
    use rpki::crypto::PublicKeyFormat;

    use krill_commons::api::DFLT_CLASS;
    use krill_commons::api::admin::{
        Handle,
        Token,
        ParentCaContact
    };
    use krill_commons::api::ca::{
        RepoInfo,
        ResourceSet,
        RcvdCert
    };
    use krill_commons::eventsourcing::{
        Aggregate,
        AggregateStore,
        DiskAggregateStore
    };
    use krill_commons::util::softsigner::OpenSslSigner;
    use krill_commons::util::test::{
        sub_dir,
        https,
        rsync,
        test_under_tmp,
    };

    use crate::ca::{
        ta_handle,
        CA_NS,
        CertAuth,
        CaIniDet,
        CaCmdDet,
        CaEvtDet,
    };

    fn signer(temp_dir: &PathBuf) -> OpenSslSigner {
        let signer_dir = sub_dir(temp_dir);
        OpenSslSigner::build(&signer_dir).unwrap()
    }

    #[test]
    fn init_ta() {
        test_under_tmp(|d| {
            let ca_store = DiskAggregateStore::<CertAuth<OpenSslSigner>>::new(
                &d, CA_NS
            ).unwrap();

            let ta_repo_info = {
                let base_uri = rsync("rsync://localhost/repo/ta/");
                let rrdp_uri = https("https://localhost/repo/notifcation.xml");
                RepoInfo::new(base_uri, rrdp_uri)
            };

            let ta_handle = ta_handle();
            let ta_token = Token::from("ta");


            let ta_uri = https("https://localhost/tal/ta.cer");
            let ta_aia = rsync("rsync://localhost/repo/ta.cer");

            let mut signer = signer(&d);
            let key = signer.create_key(PublicKeyFormat::default()).unwrap();
            let signer = Arc::new(RwLock::new(signer));

            //
            // --- Create TA and publish
            //

            let ta_ini = CaIniDet::init_ta(
                &ta_handle,
                ta_token.clone(),
                ta_repo_info,

                ta_aia,
                vec![ta_uri],
                key,

                signer.clone()
            ).unwrap();

            ca_store.add(ta_ini).unwrap();
            let ta = ca_store.get_latest(&ta_handle).unwrap();

            //
            // --- Create Child CA
            //
            // Expect:
            //   - Child CA initialised
            //
            let child_handle = Handle::from("child");
            let child_token = Token::from("child");
            let child_rs = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

            let ca_repo_info = {
                let base_uri = rsync("rsync://localhost/repo/ca/");
                let rrdp_uri = https("https://localhost/repo/notifcation.xml");
                RepoInfo::new(base_uri, rrdp_uri)
            };

            let ca_ini = CaIniDet::init(
                &child_handle,
                child_token.clone(),
                ca_repo_info
            );

            ca_store.add(ca_ini).unwrap();
            let child = ca_store.get_latest(&child_handle).unwrap();

            //
            // --- Add Child to TA
            //
            // Expect:
            //   - Child added to TA
            //

            let cmd = CaCmdDet::add_child(
                &ta_handle,
                child_handle.clone(),
                child_token.clone(),
                child_rs
            );

            let events = ta.process_command(cmd).unwrap();
            let ta = ca_store.update(&ta_handle, ta, events).unwrap();

            //
            // --- Add TA as parent to child CA
            //
            // Expect:
            //   - Parent added
            //

            let parent = ParentCaContact::for_embedded(
                ta_handle.clone(),
                child_token.clone()
            );

            let add_parent = CaCmdDet::add_parent(
                &child_handle,
                ta_handle.as_str(),
                parent
            );

            let events = child.process_command(add_parent).unwrap();
            let child = ca_store.update(&child_handle, child, events).unwrap();

            //
            // --- Get resource entitlements for Child and let it process
            //
            // Expect:
            //   - No change in TA (just read-only entitlements)
            //   - Resource Class (DFLT) added to child with pending key
            //   - Certificate requested by child
            //

            let entitlements = ta.list(&child_handle, &child_token).unwrap();

            let upd_ent = CaCmdDet::upd_entitlements(
                &child_handle,
                &ta_handle,
                entitlements,
                signer.clone()
            );

            let events = child.process_command(upd_ent).unwrap();
            assert_eq!(2, events.len()); // rc and csr
            let req_evt = events[1].clone().into_details();
            let child = ca_store.update(&child_handle, child, events).unwrap();

            let req = match req_evt {
                CaEvtDet::CertificateRequested(req) => req,
                _ => panic!("Expected Csr")
            };

            let (parent_info, class_name, limit, csr) = req.unwrap();
            assert_eq!("all", &class_name);
            assert_eq!(None, limit);
            if let ParentCaContact::Embedded(handle, token) = parent_info {
                assert_eq!(ta_handle, handle);
                assert_eq!(child_token, token);
            } else {
                panic!("Expected embedded contact")
            }

            //
            // --- Send certificate request from child to TA
            //
            // Expect:
            //   - Certificate issued
            //   - Publication
            //

            let ta_cmd = CaCmdDet::certify_child(
                &ta_handle,
                child_handle.clone(),
                csr,
                limit,
                child_token.clone(),
                signer.clone()
            );

            let ta_events = ta.process_command(ta_cmd).unwrap();
            let issued_evt = ta_events[0].clone().into_details();
            let _ta = ca_store.update(&ta_handle, ta, ta_events).unwrap();

            let (h, n, issued) = match issued_evt {
                CaEvtDet::CertificateIssued(h, n, c) => (h, n, c),
                _ => panic!("Expected issued certificate.")
            };
            assert_eq!(child_handle, h);
            assert_eq!(DFLT_CLASS, n);

            //
            // --- Return issued certificate to child CA
            //
            // Expect:
            //   - Pending key activated
            //   - Publication

            let rcvd_cert = RcvdCert::from(issued);

            let upd_rcvd = CaCmdDet::upd_received_cert(
                &child_handle, &ta_handle, DFLT_CLASS, rcvd_cert, signer.clone()
            );

            let events = child.process_command(upd_rcvd).unwrap();
            let _child = ca_store.update(&child_handle, child, events).unwrap();
        })
    }
}