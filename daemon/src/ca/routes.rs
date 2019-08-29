use std::collections::HashMap;

use rpki::crypto::KeyIdentifier;
use rpki::roa::{Roa, RoaBuilder};
use rpki::sigobj::SignedObjectBuilder;
use rpki::x509::{Serial, Time};

use krill_commons::api::ca::{RcvdCert, ReplacedObject};
use krill_commons::api::RouteAuthorization;

use crate::ca::events::RoaUpdates;
use crate::ca::{self, SignSupport, Signer};

//------------ Routes ------------------------------------------------------

/// The current authorizations and corresponding meta-information for a CA.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Routes {
    map: HashMap<RouteAuthorization, RouteInfo>,
}

impl Default for Routes {
    fn default() -> Self {
        Routes {
            map: HashMap::new(),
        }
    }
}

impl Routes {
    pub fn authorizations(&self) -> impl Iterator<Item = &RouteAuthorization> {
        self.map.keys()
    }

    pub fn info(&self, auth: &RouteAuthorization) -> Option<&RouteInfo> {
        self.map.get(auth)
    }

    pub fn has(&self, auth: &RouteAuthorization) -> bool {
        self.map.contains_key(auth)
    }

    /// Adds a new authorization, or updates an existing one.
    pub fn add(&mut self, auth: RouteAuthorization) {
        self.map.insert(auth, RouteInfo::default());
    }

    /// Removes an authorization
    pub fn remove(&mut self, auth: &RouteAuthorization) {
        self.map.remove(auth);
    }
}

//------------ RouteInfo ---------------------------------------------------

/// Meta-information about a configured RouteAuthorization.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouteInfo {
    since: Time, // authorization first added by user
}

impl Default for RouteInfo {
    fn default() -> Self {
        RouteInfo { since: Time::now() }
    }
}

//------------ RoaInfo -----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RoaInfo {
    roa: Roa,                         // actual ROA
    since: Time,                      // first ROA in RC created
    replaces: Option<ReplacedObject>, // for revoking when re-newing
}

impl RoaInfo {
    pub fn new_roa(roa: Roa) -> Self {
        RoaInfo {
            roa,
            since: Time::now(),
            replaces: None,
        }
    }

    pub fn updated_roa(old: &RoaInfo, roa: Roa) -> Self {
        let replaces = Some(ReplacedObject::from(&old.roa));
        RoaInfo {
            roa,
            since: old.since,
            replaces,
        }
    }

    pub fn roa(&self) -> &Roa {
        &self.roa
    }

    pub fn since(&self) -> Time {
        self.since
    }

    pub fn replaces(&self) -> Option<&ReplacedObject> {
        self.replaces.as_ref()
    }
}

//------------ Roas --------------------------------------------------------

/// ROAs held by a resource class in a CA.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roas {
    inner: HashMap<RouteAuthorization, RoaInfo>,
}

impl Default for Roas {
    fn default() -> Self {
        Roas {
            inner: HashMap::new(),
        }
    }
}

impl Roas {
    pub fn get(&self, auth: &RouteAuthorization) -> Option<&RoaInfo> {
        self.inner.get(auth)
    }

    pub fn updated(&mut self, updates: RoaUpdates) {
        let (updated, removed) = updates.unpack();

        for (auth, info) in updated.into_iter() {
            self.inner.insert(auth, info);
        }

        for auth in removed.keys() {
            self.inner.remove(auth);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&RouteAuthorization, &RoaInfo)> {
        self.inner.iter()
    }

    pub fn authorizations(&self) -> impl Iterator<Item = &RouteAuthorization> {
        self.inner.keys()
    }

    pub fn make_roa<S: Signer>(
        auth: &RouteAuthorization,
        incoming_cert: &RcvdCert,
        signing_key: &KeyIdentifier,
        signer: &S,
    ) -> ca::Result<Roa> {
        let prefix = auth.prefix();
        let crl_uri = incoming_cert.crl_uri();
        let roa_uri = incoming_cert.uri_for_object(auth);
        let aia = incoming_cert.uri();

        let mut roa_builder = RoaBuilder::new(auth.origin().into());
        roa_builder.push_addr(prefix.addr(), prefix.length(), prefix.max_length());

        roa_builder
            .finalize(
                SignedObjectBuilder::new(
                    Serial::random(signer).map_err(ca::Error::signer)?,
                    SignSupport::sign_validity_year(),
                    crl_uri,
                    aia.clone(),
                    roa_uri,
                ),
                signer,
                signing_key,
            )
            .map_err(ca::Error::signer)
    }
}
