use std::collections::HashMap;

use crate::commons::api::Handle;
use crate::commons::eventsourcing::{
    Aggregate, Command, CommandDetails, Event, SentCommand, StoredEvent,
};
use crate::commons::remote::api::{ClientAuth, ClientInfo};
use crate::commons::remote::id::IdCert;

// const fn is not stable yet
const ID: &str = "cms-clients";
pub fn id() -> Handle {
    Handle::from_str_unsafe(ID)
}

//------------ ClientsEvents --------------------------------------------

pub struct ClientsEvents;

impl ClientsEvents {
    pub fn init() -> ClientsInit {
        StoredEvent::new(&id(), 0, ClientsInitDetails)
    }

    pub fn added_client(version: u64, handle: Handle, client: ClientAuth) -> ClientsEvent {
        StoredEvent::new(
            &id(),
            version,
            ClientsEventDetails::AddedClient(handle, client),
        )
    }

    pub fn updated_cert(version: u64, handle: Handle, cert: IdCert) -> ClientsEvent {
        StoredEvent::new(
            &id(),
            version,
            ClientsEventDetails::UpdatedClientCert(handle, cert),
        )
    }

    pub fn removed_client(version: u64, handle: Handle) -> ClientsEvent {
        StoredEvent::new(&id(), version, ClientsEventDetails::RemovedClient(handle))
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ClientsInitDetails;

pub type ClientsInit = StoredEvent<ClientsInitDetails>;

#[derive(Clone, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ClientsEventDetails {
    AddedClient(Handle, ClientAuth),
    UpdatedClientCert(Handle, IdCert),
    RemovedClient(Handle),
}

pub type ClientsEvent = StoredEvent<ClientsEventDetails>;

//------------ ClientsCommands -------------------------------------------

pub struct ClientsCommands;

impl ClientsCommands {
    pub fn add(handle: Handle, client: ClientAuth) -> ClientsCommand {
        SentCommand::new(
            &id(),
            None,
            ClientsCommandDetails::AddClient(handle, client),
        )
    }
    pub fn update_cert(handle: Handle, cert: IdCert) -> ClientsCommand {
        SentCommand::new(
            &id(),
            None,
            ClientsCommandDetails::UpdateClientCert(handle, cert),
        )
    }
    pub fn remove(handle: Handle) -> ClientsCommand {
        SentCommand::new(&id(), None, ClientsCommandDetails::RemoveClient(handle))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ClientsCommandDetails {
    AddClient(Handle, ClientAuth),
    UpdateClientCert(Handle, IdCert),
    RemoveClient(Handle),
}

impl CommandDetails for ClientsCommandDetails {
    type Event = StoredEvent<ClientsEventDetails>;
}

pub type ClientsCommand = SentCommand<ClientsCommandDetails>;

//------------ ClientManager -------------------------------------------------

/// This type manages the known clients for the CMS proxy server. I.e. it
/// knows which clients are configured, the client certificates that they use
/// to connect to the proxy server, and the token that the krill server JSON API
/// expects.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientManager {
    // Aggregate version
    version: u64,

    // Clients known by this proxy
    clients: HashMap<Handle, ClientAuth>,
}

impl Aggregate for ClientManager {
    type Command = ClientsCommand;
    type Event = ClientsEvent;
    type InitEvent = ClientsInit;
    type Error = Error;

    fn init(_event: Self::InitEvent) -> Result<Self, Error> {
        let version = 1;
        let clients = HashMap::new();

        Ok(ClientManager { version, clients })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Self::Event) {
        if event.version() != self.version {
            panic!(
                "Cannot apply event for version {}, to aggregate version {}",
                event.version(),
                self.version
            )
        }
        match event.into_details() {
            ClientsEventDetails::AddedClient(handle, client) => {
                self.clients.insert(handle, client);
            }
            ClientsEventDetails::UpdatedClientCert(handle, id_cert) => {
                self.clients.get_mut(&handle).unwrap().set_cert(id_cert);
            }
            ClientsEventDetails::RemovedClient(handle) => {
                self.clients.remove(&handle);
            }
        }

        self.version += 1;
    }

    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        if let Some(version) = command.version() {
            if version != self.version {
                return Err(Error::ConcurrentModification(version, self.version));
            }
        }

        let mut res = vec![];

        match command.into_details() {
            ClientsCommandDetails::AddClient(handle, client) => {
                self.assert_new(&handle)?;
                res.push(ClientsEvents::added_client(self.version, handle, client))
            }
            ClientsCommandDetails::UpdateClientCert(handle, cert) => {
                self.assert_exists(&handle)?;
                res.push(ClientsEvents::updated_cert(self.version, handle, cert))
            }
            ClientsCommandDetails::RemoveClient(handle) => {
                self.assert_exists(&handle)?;
                res.push(ClientsEvents::removed_client(self.version, handle))
            }
        }

        Ok(res)
    }
}

impl ClientManager {
    pub fn client_auth(&self, handle: &Handle) -> Option<&ClientAuth> {
        self.clients.get(handle)
    }

    pub fn list(&self) -> Vec<ClientInfo> {
        let mut res = vec![];
        for (handle, auth) in self.clients.iter() {
            res.push(ClientInfo::new(handle.clone(), auth.clone()));
        }
        res
    }

    fn has_client(&self, handle: &Handle) -> bool {
        self.clients.contains_key(handle)
    }

    fn assert_new(&self, handle: &Handle) -> ProxyResult<()> {
        if self.has_client(handle) {
            Err(Error::ClientExists(handle.clone()))
        } else {
            Ok(())
        }
    }

    fn assert_exists(&self, handle: &Handle) -> ProxyResult<()> {
        if !self.has_client(handle) {
            Err(Error::NoClient(handle.clone()))
        } else {
            Ok(())
        }
    }
}

type ProxyResult<T> = Result<T, Error>;

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Received command for version: {}, but am version: {}", _0, _1)]
    ConcurrentModification(u64, u64),

    #[display(fmt = "Client with handle {} cannot be added (already exists)", _0)]
    ClientExists(Handle),

    #[display(fmt = "Client with handle {} does not exist", _0)]
    NoClient(Handle),
}

impl std::error::Error for Error {}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
pub mod tests {

    use std::path::PathBuf;

    use rpki::crypto::PublicKeyFormat;
    use rpki::crypto::Signer;

    use crate::commons::eventsourcing::AggregateStore;
    use crate::commons::eventsourcing::DiskAggregateStore;
    use crate::commons::remote::builder::IdCertBuilder;
    use crate::commons::util::softsigner::OpenSslSigner;
    use crate::commons::util::test;

    use super::*;

    pub fn new_id_cert(work_dir: &PathBuf) -> IdCert {
        let mut s = OpenSslSigner::build(work_dir).unwrap();
        let key_id = s.create_key(PublicKeyFormat::default()).unwrap();
        IdCertBuilder::new_ta_id_cert(&key_id, &s).unwrap()
    }

    pub fn add_client(work_dir: &PathBuf, name: &str) -> ClientsCommand {
        let cert = new_id_cert(work_dir);
        let handle = Handle::from_str_unsafe(name);

        ClientsCommands::add(handle, ClientAuth::new(cert))
    }

    #[test]
    fn should_manage_clients() {
        test::test_under_tmp(|d| {
            // Set up a store for the proxy
            let store = DiskAggregateStore::<ClientManager>::new(&d, "proxy").unwrap();

            // Create the proxy server in the store
            let init = ClientsEvents::init();
            store.add(init).unwrap();

            // Get the proxy for use
            let proxy = store.get_latest(&id()).unwrap();
            assert_eq!(1, proxy.version());

            // Set up client "alice" and add to the proxy
            let alice_cert1 = new_id_cert(&d);
            let alice_handle = Handle::from_str_unsafe("alice");

            let add_alice =
                ClientsCommands::add(alice_handle.clone(), ClientAuth::new(alice_cert1.clone()));

            let events = proxy.process_command(add_alice).unwrap();
            assert_eq!(1, events.len());
            let proxy = store.update(&id(), proxy, events).unwrap();

            // Verify that "alice" was added.
            let alice = proxy.client_auth(&alice_handle).unwrap();
            assert_eq!(alice_cert1.to_bytes(), alice.cert().to_bytes());

            // Verify that "alice" is still known when we start up again
            // i.e. clear the cache and read from disk.
            let store = DiskAggregateStore::<ClientManager>::new(&d, "proxy").unwrap();
            let proxy = store.get_latest(&id()).unwrap();

            {
                let alice = proxy.client_auth(&alice_handle).unwrap();
                assert_eq!(alice_cert1.to_bytes(), alice.cert().to_bytes());
            }

            // Update cert
            let alice_cert2 = new_id_cert(&d);
            let update_alice_cert =
                ClientsCommands::update_cert(alice_handle.clone(), alice_cert2.clone());

            let events = proxy.process_command(update_alice_cert).unwrap();
            assert_eq!(1, events.len());
            let proxy = store.update(&id(), proxy, events).unwrap();

            {
                let alice = proxy.client_auth(&alice_handle).unwrap();
                assert_eq!(alice_cert2.to_bytes(), alice.cert().to_bytes());
            }

            // Remove alice
            let remove_alice = ClientsCommands::remove(alice_handle.clone());
            let events = proxy.process_command(remove_alice).unwrap();
            assert_eq!(1, events.len());
            let proxy = store.update(&id(), proxy, events).unwrap();

            assert!(proxy.client_auth(&alice_handle).is_none());
        })
    }
}
