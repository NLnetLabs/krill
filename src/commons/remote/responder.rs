use crate::commons::api::Handle;
use crate::commons::eventsourcing::{Aggregate, CommandDetails, SentCommand, StoredEvent};

use super::id::MyIdentity;

// const fn is not stable yet
const ID: &str = "cms-responder";
pub fn id() -> Handle {
    Handle::from_str_unsafe(ID)
}

//------------ ResponderEvent ---------------------------------------------

#[derive(Clone, Deserialize, Serialize)]
pub struct ResponderInitDetails {
    id: MyIdentity,
}

pub type ResponderInit = StoredEvent<ResponderInitDetails>;

#[derive(Clone, Deserialize, Serialize)]
pub struct ResponderEventDetails; // in future: update identity or uri

pub type ResponderEvent = StoredEvent<ResponderEventDetails>;

pub struct ResponderEvents;
impl ResponderEvents {
    pub fn init(my_id: MyIdentity) -> ResponderInit {
        StoredEvent::new(&id(), 0, ResponderInitDetails { id: my_id })
    }
}

//------------ ResponderCommand --------------------------------------------

#[derive(Clone, Deserialize, Serialize)]
pub struct ResponderCommandDetails; // in future: update identity or uri

impl CommandDetails for ResponderCommandDetails {
    type Event = ResponderEvent;
}

pub type ResponderCommand = SentCommand<ResponderCommandDetails>;

//------------ Responder ---------------------------------------------------

/// This type is responsible for signing requests to clients.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Responder {
    // Aggregate version
    version: u64,

    // How this server is known to clients
    id: MyIdentity,
}

impl Aggregate for Responder {
    type Command = ResponderCommand;
    type Event = ResponderEvent;
    type InitEvent = ResponderInit;
    type Error = Error;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        let id = event.into_details().id;
        let version = 1;
        Ok(Responder { version, id })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, _event: Self::Event) {
        // There are no events yet, beyond init.
        unimplemented!()
    }

    fn process_command(&self, _command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        // There are no commands yet, beyond init. Will support updating id and krill_uri in future
        unimplemented!()
    }
}

impl Responder {
    pub fn id(&self) -> &MyIdentity {
        &self.id
    }
}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Received command for version: {}, but am version: {}", _0, _1)]
    ConcurrentModification(u64, u64),
}

impl std::error::Error for Error {}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rpki::crypto::PublicKeyFormat;
    use rpki::crypto::Signer;

    use crate::commons::eventsourcing::AggregateStore;
    use crate::commons::eventsourcing::DiskAggregateStore;
    use crate::commons::remote::builder::IdCertBuilder;
    use crate::commons::util::softsigner::OpenSslSigner;
    use crate::commons::util::test;

    use super::*;

    pub fn new_id(work_dir: &PathBuf) -> MyIdentity {
        let mut s = OpenSslSigner::build(work_dir).unwrap();
        let key_id = s.create_key(PublicKeyFormat::default()).unwrap();
        let id_cert = IdCertBuilder::new_ta_id_cert(&key_id, &s).unwrap();
        let name = Handle::from_str_unsafe("krill-proxy");
        MyIdentity::new(name, id_cert, key_id)
    }

    #[test]
    fn should_init() {
        test::test_under_tmp(|d| {
            // Set up a store for the proxy
            let store = DiskAggregateStore::<Responder>::new(&d, "proxy").unwrap();

            // Create the proxy server in the store
            let my_id = new_id(&d);

            let init = ResponderEvents::init(my_id);
            store.add(init).unwrap();
        });
    }

}
