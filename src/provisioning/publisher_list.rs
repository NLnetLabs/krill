//! Responsible for storing and retrieving Publisher information.
use std::str;
use rpki::oob::exchange::PublisherRequest;
use rpki::remote::idcert::IdCert;
use rpki::uri;


//------------ Publisher -----------------------------------------------------

/// This type defines Publisher CAs that are allowed to publish.
#[derive(Debug)]
pub struct Publisher {
    name:       String,
    base_uri:   uri::Rsync,
    id_cert:    IdCert
}


//------------ PublisherListCommand ------------------------------------------

// These are the commands to send to the PublisherList that allow updating the
// list of Publishers.
#[derive(Debug)]
pub enum PublisherListCommand {
    Add(PublisherRequest)
}

#[derive(Debug)]
pub struct VersionedPublisherListCommand {
    version: usize,
    command: PublisherListCommand
}

impl VersionedPublisherListCommand {
    pub fn publisher_request(
        version: usize,
        pr: PublisherRequest
    ) -> Self {
        VersionedPublisherListCommand {
            version,
            command: PublisherListCommand::Add(pr)
        }
    }
}

//------------ PublisherListEvent --------------------------------------------

// These are the events that occurred on the PublisherList. Together they
// form a complete audit trail, and when replayed in order will result in
// the current state of the PublisherList.
#[derive(Debug)]
pub enum PublisherListEvent {
    Added(PublisherAdded),
    CertUpdated(PublisherIdUpdated),
    Removed(PublisherRemoved)
}

#[derive(Debug)]
pub struct VersionedPublisherListEvent {
    version: usize,
    event: PublisherListEvent
}

#[derive(Debug)]
pub struct PublisherAdded(Publisher);

#[derive(Debug)]
pub struct PublisherIdUpdated(String);

#[derive(Debug)]
pub struct PublisherRemoved(String);


//------------ PublisherList -------------------------------------------------

#[derive(Debug)]
pub struct PublisherList {
    /// The version of this list. This gets updated with every modification.
    version: usize,

    /// The base URI for this repository server. Publishers will get a
    /// directory below this based on their 'publisher_handle'.
    base_uri: uri::Rsync,

    /// The current configured publishers.
    publishers: Vec<Publisher>
}


impl PublisherList {

    pub fn new(base_uri: uri::Rsync) -> Self {
        PublisherList {
            version: 0,
            base_uri,
            publishers: Vec::new()
        }
    }

    pub fn apply_event(
        &mut self,
        event: &VersionedPublisherListEvent
    ) -> Result<(), PublisherListError> {

        if self.version != event.version {
            return Err(PublisherListError::VersionConflict(self.version, event.version))
        }

        self.version = self.version + 1;

        Ok(())
    }

    pub fn apply_command(
        &mut self,
        command: VersionedPublisherListCommand
    ) -> Result<VersionedPublisherListEvent, PublisherListError> {

        if self.version != command.version {
            return Err(PublisherListError::VersionConflict(self.version, command.version))
        }

        match command.command {
            PublisherListCommand::Add(pr) => self
                .process_publisher_request(pr)
        }
    }

    fn process_publisher_request(
        &mut self,
        pr: PublisherRequest
    ) -> Result<VersionedPublisherListEvent, PublisherListError> {

        let (_, name, id_cert) = pr.into_parts();

        if name.contains("/") {
            return Err(
                PublisherListError::ForwardSlashInHandle(name))
        }

        let mut base_uri = self.base_uri.to_string();
        base_uri.push_str("/");
        base_uri.push_str(name.as_ref());
        let base_uri = uri::Rsync::from_string(base_uri)?;

        let publisher = Publisher { name, base_uri, id_cert };

        let event = VersionedPublisherListEvent {
            version: self.version,
            event: PublisherListEvent::Added(PublisherAdded(publisher))
        };

        self.apply_event(&event)?;

        Ok(event)
    }

}


//------------ PublisherListError --------------------------------------------

#[derive(Debug, Fail)]
pub enum PublisherListError {

    #[fail(display =
        "Version conflict. Current version is: {},update has: {}", _0, _1)]
    VersionConflict(usize, usize),

    #[fail(display =
        "The '/' in publisher_handle ({}) is not supported - because we \
        are deriving the base directory for a publisher from this. This \
        behaviour may be updated in future.", _0)]
    ForwardSlashInHandle(String),

    #[fail(display = "Error in base URI: {}.", _0)]
    UriError(uri::Error)
}

impl From<uri::Error> for PublisherListError {
    fn from(e: uri::Error) -> Self {
        PublisherListError::UriError(e)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use rpki::signing::signer::Signer;
    use rpki::signing::softsigner::OpenSslSigner;
    use rpki::signing::PublicKeyAlgorithm;
    use rpki::signing::builder::IdCertBuilder;



    fn rsync_uri(s: &str) -> uri::Rsync {
        uri::Rsync::from_str(s).unwrap()
    }

    fn empty_publisher_list() -> PublisherList {
        let base_uri = rsync_uri("rsync://host/module/");
        PublisherList::new(base_uri)
    }

    fn new_id_cert() -> IdCert {
        let mut s = OpenSslSigner::new();
        let key_id = s.create_key(&PublicKeyAlgorithm::RsaEncryption).unwrap();
        IdCertBuilder::new_ta_id_cert(&key_id, &mut s).unwrap()
    }

    #[test]
    fn should_add_publisher() {
        let mut cl = empty_publisher_list();
        let id_cert = new_id_cert();

        let pr = PublisherRequest::new(
            Some("test"),
            "test",
            id_cert);

        let cmd = VersionedPublisherListCommand::publisher_request(0, pr);
        cl.apply_command(cmd).unwrap();
    }

    #[test]
    fn should_refuse_slash_in_publisher_handle() {
        let mut cl = empty_publisher_list();
        let id_cert = new_id_cert();

        let pr = PublisherRequest::new(
            Some("test"),
            "test/below",
            id_cert);

        let cmd = VersionedPublisherListCommand::publisher_request(0, pr);
        match cl.apply_command(cmd) {
            Err(PublisherListError::ForwardSlashInHandle(_)) => { }, // Ok
            _ => panic!("Should have seen error.")
        }
    }


}