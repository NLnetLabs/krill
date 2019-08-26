use std::collections::HashMap;

use rpki::roa::Roa;
use rpki::x509::Time;

use krill_commons::api::ca::{ReplacedObject, ResourceClassName};
use krill_commons::api::RouteAuthorization;

use crate::ca::events::{RouteAuthorizationRemoval, RouteAuthorizationUpdate};

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
    pub fn update(&mut self, update: RouteAuthorizationUpdate) {
        let (authorization, roas) = update.unpack();

        match self.map.get_mut(&authorization) {
            Some(info) => info.update(roas),
            None => {
                self.map.insert(authorization, RouteInfo::new(roas));
            }
        }
    }

    /// Removes an authorization
    pub fn remove(&mut self, removal: &RouteAuthorizationRemoval) {
        self.map.remove(removal.authorization());
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouteInfo {
    since: Time,                               // authorization first added by user
    roas: HashMap<ResourceClassName, RoaInfo>, // actual ROAs (may become empty)
}

impl RouteInfo {
    pub fn new(roas: HashMap<ResourceClassName, RoaInfo>) -> Self {
        RouteInfo {
            since: Time::now(),
            roas,
        }
    }

    pub fn update(&mut self, roas: HashMap<ResourceClassName, RoaInfo>) {
        for (rcn, roa_info) in roas.into_iter() {
            self.roas.insert(rcn, roa_info);
        }
    }

    pub fn roas(&self) -> &HashMap<ResourceClassName, RoaInfo> {
        &self.roas
    }
}

impl Default for RouteInfo {
    fn default() -> Self {
        RouteInfo {
            since: Time::now(),
            roas: HashMap::new(),
        }
    }
}

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
