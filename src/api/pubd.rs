use std::fmt;
use std::collections::HashMap;
use rpki::uri;
use rpki::ca::idexchange::PublisherHandle;
use rpki::repository::{x509::Time, Manifest};
use serde::{Deserialize, Serialize};
use uuid::Uuid;


//------------ RepoStats -----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepoStats {
    pub publishers: HashMap<PublisherHandle, PublisherStats>,
    pub session: Uuid,
    pub serial: u64,
    pub last_update: Option<Time>,
    pub rsync_base: uri::Rsync,
    pub rrdp_base: uri::Https,
}

impl RepoStats {
    pub fn stale_publishers(
        self, seconds: i64
    ) -> impl Iterator<Item = PublisherHandle> {
        self.publishers.into_iter().filter_map(move |(publisher, stats)| {
            if let Some(update_time) = stats.last_update() {
                if Time::now().timestamp() - update_time.timestamp()
                    >= seconds
                {
                    Some(publisher)
                }
                else {
                    None
                }
            } else {
                Some(publisher)
            }
        })
    }
}

impl fmt::Display for RepoStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Server URIs:")?;
        writeln!(f, "    rrdp:    {}", self.rrdp_base)?;
        writeln!(f, "    rsync:   {}", self.rsync_base)?;
        writeln!(f)?;
        if let Some(update) = self.last_update {
            writeln!(f, "RRDP updated:      {}", update.to_rfc3339())?;
        }
        writeln!(f, "RRDP session:      {}", self.session)?;
        writeln!(f, "RRDP serial:       {}", self.serial)?;
        writeln!(f)?;
        writeln!(f, "Publisher, Objects, Size, Last Updated")?;
        for (publisher, stats) in &self.publishers {
            let update_str = match stats.last_update() {
                None => "never".to_string(),
                Some(update) => update.to_rfc3339(),
            };
            writeln!(
                f,
                "{}, {}, {}, {}",
                publisher,
                stats.objects,
                stats.size,
                update_str
            )?;
        }

        Ok(())
    }
}


//------------ PublisherStats ------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherStats {
    pub objects: usize,
    pub size: usize,
    pub manifests: Vec<PublisherManifestStats>,
}

impl PublisherStats {
    /// Returns the most recent "this_update" time
    /// from all manifest(s) published by this publisher,
    /// if any.. i.e. there may be 0, 1 or many manifests
    pub fn last_update(&self) -> Option<Time> {
        let mut last_update = None;
        for mft in &self.manifests {
            if let Some(last_update_until_now) = last_update {
                let this_manifest_this_update = mft.this_update;
                if this_manifest_this_update > last_update_until_now {
                    last_update = Some(this_manifest_this_update)
                }
            } else {
                last_update = Some(mft.this_update);
            }
        }

        last_update
    }
}


//------------ PublisherManifestStats ----------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherManifestStats {
    pub uri: uri::Rsync,
    pub this_update: Time,
    pub next_update: Time,
}

impl TryFrom<&Manifest> for PublisherManifestStats {
    type Error = ();

    // This will fail for syntactically incorrect manifests, which do
    // not include the signed object URI in their SIA.
    fn try_from(mft: &Manifest) -> Result<Self, Self::Error> {
        let uri = mft.cert().signed_object().cloned().ok_or(())?;
        Ok(PublisherManifestStats {
            uri,
            this_update: mft.this_update(),
            next_update: mft.next_update(),
        })
    }
}

