use std::collections::HashMap;
use krill_commons::api::admin::Token;
use krill_commons::eventsourcing::{
    Aggregate,
    AggregateId,
    Command,
    CommandDetails,
    Event,
    SentCommand,
    StoredEvent
};
use crate::api::{
    ClientAuth,
    ClientHandle,
};
use crate::id::IdCert;
use api::ClientInfo;

// const fn is not stable yet
const ID: &str = "cms-clients";
pub fn id() -> AggregateId { AggregateId::from(ID) }



//------------ ClientsEvents --------------------------------------------

pub struct ClientsEvents;

impl ClientsEvents {
    pub fn init() -> ClientsInit {
        StoredEvent::new(&id(), 0, ClientsInitDetails)
    }

    pub fn added_client(version: u64, handle: ClientHandle, client: ClientAuth) -> ClientsEvent {
        StoredEvent::new(&id(), version, ClientsEventDetails::AddedClient(handle, client))
    }

    pub fn updated_cert(version: u64, handle: ClientHandle, cert: IdCert) -> ClientsEvent {
        StoredEvent::new(&id(), version, ClientsEventDetails::UpdatedClientCert(handle, cert))
    }

    pub fn updated_token(version: u64, handle: ClientHandle, token: Token) -> ClientsEvent {
        StoredEvent::new(&id(), version, ClientsEventDetails::UpdatedClientToken(handle, token))
    }

    pub fn removed_client(version: u64, handle: ClientHandle) -> ClientsEvent {
        StoredEvent::new(&id(), version, ClientsEventDetails::RemovedClient(handle))
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ClientsInitDetails;

pub type ClientsInit = StoredEvent<ClientsInitDetails>;

#[derive(Clone, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ClientsEventDetails {
    AddedClient(ClientHandle, ClientAuth),
    UpdatedClientCert(ClientHandle, IdCert),
    UpdatedClientToken(ClientHandle, Token),
    RemovedClient(ClientHandle)
}

pub type ClientsEvent = StoredEvent<ClientsEventDetails>;


//------------ ClientsCommands -------------------------------------------

pub struct ClientsCommands;

impl ClientsCommands {
    pub fn add(handle: ClientHandle, client: ClientAuth) -> ClientsCommand {
        SentCommand::new(&id(), None, ClientsCommandDetails::AddClient(handle, client))
    }
    pub fn update_cert(handle: ClientHandle, cert: IdCert) -> ClientsCommand {
        SentCommand::new(&id(), None, ClientsCommandDetails::UpdateClientCert(handle, cert))
    }
    pub fn update_token(handle: ClientHandle, token: Token) -> ClientsCommand {
        SentCommand::new(&id(), None, ClientsCommandDetails::UpdateClientToken(handle, token))
    }
    pub fn remove(handle: ClientHandle) -> ClientsCommand {
        SentCommand::new(&id(), None, ClientsCommandDetails::RemoveClient(handle))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ClientsCommandDetails {
    AddClient(ClientHandle, ClientAuth),
    UpdateClientCert(ClientHandle, IdCert),
    UpdateClientToken(ClientHandle, Token),
    RemoveClient(ClientHandle)
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
    clients: HashMap<ClientHandle, ClientAuth>
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
            ClientsEventDetails::AddedClient(handle, client)   => {
                self.clients.insert(handle, client);
            },
            ClientsEventDetails::UpdatedClientCert(handle, id_cert) => {
                self.clients.get_mut(&handle).unwrap().set_cert(id_cert);
            },
            ClientsEventDetails::RemovedClient(handle) => {
                self.clients.remove(&handle);
            }
            ClientsEventDetails::UpdatedClientToken(handle, token) => {
                self.clients.get_mut(&handle).unwrap().set_token(token);
            }
        }

        self.version += 1;
    }

    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        if let Some(version) = command.version() {
            if version != self.version {
                return Err(Error::ConcurrentModification(version, self.version))
            }
        }

        let mut res = vec![];

        match command.into_details() {
            ClientsCommandDetails::AddClient(handle, client) => {
                self.assert_new(&handle)?;
                res.push(ClientsEvents::added_client(self.version, handle, client))
            },
            ClientsCommandDetails::UpdateClientCert(handle, cert) => {
                self.assert_exists(&handle)?;
                res.push(ClientsEvents::updated_cert(self.version, handle, cert))
            },
            ClientsCommandDetails::UpdateClientToken(handle, token) => {
                self.assert_exists(&handle)?;
                res.push(ClientsEvents::updated_token(self.version, handle, token))
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
    pub fn client_auth(&self, handle: &ClientHandle) -> Option<&ClientAuth> {
        self.clients.get(handle)
    }

    pub fn list(&self) -> Vec<ClientInfo> {
        let mut res = vec![];
        for (handle, auth) in self.clients.iter() {
           res.push(ClientInfo::new(handle.clone(), auth.clone()));
        };
        res
    }

    fn has_client(&self, handle: &ClientHandle) -> bool {
        self.clients.contains_key(handle)
    }

    fn assert_new(&self, handle: &ClientHandle) -> ProxyResult<()> {
        if self.has_client(handle) {
            Err(Error::ClientExists(handle.clone()))
        } else { Ok(()) }
    }


    fn assert_exists(&self, handle: &ClientHandle) -> ProxyResult<()> {
        if ! self.has_client(handle) {
            Err(Error::NoClient(handle.clone()))
        } else { Ok(()) }
    }
}

type ProxyResult<T> = Result<T, Error>;


//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Received command for version: {}, but am version: {}", _0, _1)]
    ConcurrentModification(u64, u64),

    #[display(fmt = "Client with handle {} cannot be added (already exists)", _0)]
    ClientExists(ClientHandle),

    #[display(fmt = "Client with handle {} does not exist", _0)]
    NoClient(ClientHandle),
}

impl std::error::Error for Error {}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
pub mod tests {

    use super::*;
    use std::path::PathBuf;
    use krill_commons::util::test;
    use krill_commons::eventsourcing::AggregateStore;
    use krill_commons::eventsourcing::DiskAggregateStore;
    use krill_commons::util::softsigner::OpenSslSigner;
    use rpki::crypto::PublicKeyFormat;
    use rpki::crypto::Signer;
    use crate::builder::IdCertBuilder;

    pub fn new_id_cert(work_dir: &PathBuf) -> IdCert {
        let mut s = OpenSslSigner::build(work_dir).unwrap();
        let key_id = s.create_key(PublicKeyFormat::default()).unwrap();
        IdCertBuilder::new_ta_id_cert(&key_id, &mut s).unwrap()
    }

    pub fn add_client(work_dir: &PathBuf, name: &str) -> ClientsCommand {
        let cert = new_id_cert(work_dir);
        let token = Token::from(name);
        let handle = ClientHandle::from(name);

        ClientsCommands::add(
            handle,
            ClientAuth::new(cert, token)
        )
    }


    #[test]
    fn should_manage_clients() {
        test::test_with_tmp_dir(|d| {

            // Set up a store for the proxy
            let store = DiskAggregateStore::<ClientManager>::new(&d, "proxy").unwrap();

            // Create the proxy server in the store
            let init = ClientsEvents::init();
            store.add(&id(), init).unwrap();

            // Get the proxy for use
            let proxy = store.get_latest(&id()).unwrap();
            assert_eq!(1, proxy.version());

            // Set up client "alice" and add to the proxy
            let alice_cert1 = new_id_cert(&d);
            let alice_token1 = Token::from("alice1");
            let alice_handle = ClientHandle::from("alice");

            let add_alice = ClientsCommands::add(
                alice_handle.clone(),
                ClientAuth::new(alice_cert1.clone(), alice_token1.clone())
            );

            let events = proxy.process_command(add_alice).unwrap();
            assert_eq!(1, events.len());
            let proxy = store.update(&id(), proxy, events).unwrap();

            // Verify that "alice" was added.
            let alice = proxy.client_auth(&alice_handle).unwrap();

            assert_eq!(alice_cert1.to_bytes(), alice.cert().to_bytes());
            assert_eq!(&alice_token1, alice.token());

            // Verify that "alice" is still known when we start up again
            // i.e. clear the cache and read from disk.
            let store = DiskAggregateStore::<ClientManager>::new(&d, "proxy").unwrap();
            let proxy = store.get_latest(&id()).unwrap();

            {
                let alice = proxy.client_auth(&alice_handle).unwrap();
                assert_eq!(alice_cert1.to_bytes(), alice.cert().to_bytes());
                assert_eq!(&alice_token1, alice.token());
            }

            // Update token
            let alice_token2 = Token::from("alice2");
            let update_alice_token = ClientsCommands::update_token(
                alice_handle.clone(),
                alice_token2.clone()
            );

            let events = proxy.process_command(update_alice_token).unwrap();
            assert_eq!(1, events.len());

            let proxy = store.update(&id(), proxy, events).unwrap();
            {
                let alice = proxy.client_auth(&alice_handle).unwrap();
                assert_eq!(&alice_token2, alice.token());
            }

            // Update cert
            let alice_cert2 = new_id_cert(&d);
            let update_alice_cert = ClientsCommands::update_cert(
                alice_handle.clone(),
                alice_cert2.clone()
            );

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
