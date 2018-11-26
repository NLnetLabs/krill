use ext_serde;
use rpki::uri;
use bytes::Bytes;
use rpki::publication;
use rpki::publication::query::{ Publish, PublishElement, Update, Withdraw };

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CurrentFile {
    #[serde(
    deserialize_with = "ext_serde::de_rsync_uri",
    serialize_with = "ext_serde::ser_rsync_uri")]
    uri:     uri::Rsync,

    #[serde(
    deserialize_with = "ext_serde::de_bytes",
    serialize_with = "ext_serde::ser_bytes")]
    /// The actual file content. Note that we may want to store this
    /// only on disk in future (look up by sha256 hash), to save memory.
    content: Bytes,

    #[serde(
    deserialize_with = "ext_serde::de_bytes",
    serialize_with = "ext_serde::ser_bytes")]
    /// The sha-256 hash of the file (as is used on the RPKI manifests and
    /// in the publication protocol for list, update and withdraw). Saving
    /// this rather than calculating on demand seems a small price for some
    /// performance gain.
    hash:    Bytes
}

impl CurrentFile {
    pub fn new(uri: uri::Rsync, content: Bytes) -> Self {
        let hash = publication::hash(&content);
        CurrentFile {uri, content, hash}
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    pub fn content(&self) -> &Bytes {
        &self.content
    }

    pub fn hash(&self) -> &Bytes {
        &self.hash
    }

    pub fn as_publish(&self) -> PublishElement {
        Publish::publish(&self.content, self.uri.clone())
    }

    pub fn as_update(&self, old_content: &Bytes) -> PublishElement {
        Update::publish(old_content, &self.content, self.uri.clone())
    }

    pub fn as_withdraw(&self) -> PublishElement {
        Withdraw::publish(&self.content, self.uri.clone())
    }
}

impl PartialEq for CurrentFile {
    fn eq(&self, other: &CurrentFile) -> bool {
        self.uri == other.uri &&
            self.hash == other.hash &&
            self.content == other.content
    }
}

impl Eq for CurrentFile {}