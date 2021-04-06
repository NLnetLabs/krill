//! All actions performed by Krill are authorized by and attributed to an Actor.
//!
//! An Actor either represents Krill itself or an external client of Krill.
//! Actors can only be created by the [Authorizer](crate::daemon::auth::Authorizer).
//!
//! An [ActorDef] defines an Actor that can be created later.
//!
//! ActorDefs allows special internal actors to be described once as Rust
//! constants and turned into actual Actors at the point where they are needed.
//!
//! ActorDefs also allow [AuthProvider](crate::daemon::auth::authorizer::AuthProvider)s
//! to define the Actor that should be created without needing any knowledge of
//! the Authorizer.

#[cfg(feature = "multi-user")]
use oso::ToPolar;
#[cfg(feature = "multi-user")]
use std::fmt::Display;

use crate::commons::error::{ApiAuthError, Error};
use crate::daemon::auth::policy::AuthPolicy;
use crate::{commons::KrillResult, constants::ACTOR_DEF_ANON, daemon::auth::Auth};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ActorName {
    AsStaticStr(&'static str),
    AsString(String),
}

impl ActorName {
    pub fn as_str(&self) -> &str {
        match &self {
            ActorName::AsStaticStr(s) => s,
            ActorName::AsString(s) => s,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Attributes {
    None,
    RoleOnly(&'static str),
    UserDefined(HashMap<String, String>),
}

impl Attributes {
    pub fn as_map(&self) -> HashMap<String, String> {
        match &self {
            Attributes::UserDefined(map) => map.clone(),
            Attributes::RoleOnly(role) => {
                let mut map = HashMap::new();
                map.insert("role".to_string(), role.to_string());
                map
            }
            Attributes::None => HashMap::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ActorDef {
    pub name: ActorName,
    pub is_user: bool,
    pub attributes: Attributes,
    pub new_auth: Option<Auth>,
    pub auth_error: Option<ApiAuthError>,
}

impl ActorDef {
    pub const fn anonymous() -> ActorDef {
        ActorDef {
            name: ActorName::AsStaticStr("anonymous"),
            is_user: false,
            attributes: Attributes::None,
            new_auth: None,
            auth_error: None,
        }
    }

    pub const fn system(name: &'static str, role: &'static str) -> ActorDef {
        ActorDef {
            name: ActorName::AsStaticStr(name),
            attributes: Attributes::RoleOnly(role),
            is_user: false,
            new_auth: None,
            auth_error: None,
        }
    }

    pub fn user(name: String, attributes: HashMap<String, String>, new_auth: Option<Auth>) -> ActorDef {
        ActorDef {
            name: ActorName::AsString(name),
            is_user: true,
            attributes: Attributes::UserDefined(attributes),
            new_auth,
            auth_error: None,
        }
    }

    // Takes either a ApiAuthError or a commons::error::Error
    pub fn with_auth_error(mut self, api_error: Error) -> Self {
        self.auth_error = Some(api_error.into());
        self
    }
}

#[derive(Clone)]
pub struct Actor {
    name: ActorName,
    is_user: bool,
    attributes: Attributes,
    new_auth: Option<Auth>,
    policy: Option<AuthPolicy>,
    auth_error: Option<ApiAuthError>,
}

impl PartialEq for Actor {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.is_user == other.is_user && self.attributes == other.attributes
    }
}

impl PartialEq<ActorDef> for Actor {
    fn eq(&self, other: &ActorDef) -> bool {
        self.name == other.name && self.is_user == other.is_user && self.attributes == other.attributes
    }
}

impl Actor {
    /// Only for use in testing
    pub fn test_from_def(repr: ActorDef) -> Actor {
        Actor {
            name: repr.name.clone(),
            is_user: repr.is_user,
            attributes: repr.attributes,
            new_auth: None,
            auth_error: None,
            policy: None,
        }
    }

    /// Only for use in testing
    pub fn test_from_details(name: String, attrs: HashMap<String, String>) -> Actor {
        Actor {
            name: ActorName::AsString(name),
            attributes: Attributes::UserDefined(attrs),
            is_user: false,
            new_auth: None,
            auth_error: None,
            policy: None,
        }
    }

    pub fn new(repr: ActorDef, policy: AuthPolicy) -> Actor {
        Actor {
            name: repr.name.clone(),
            is_user: repr.is_user,
            attributes: repr.attributes.clone(),
            new_auth: repr.new_auth.clone(),
            auth_error: repr.auth_error,
            policy: Some(policy),
        }
    }

    pub fn is_user(&self) -> bool {
        self.is_user
    }

    pub fn is_anonymous(&self) -> bool {
        self == &ACTOR_DEF_ANON
    }

    pub fn new_auth(&self) -> Option<Auth> {
        self.new_auth.clone()
    }

    pub fn attributes(&self) -> HashMap<String, String> {
        self.attributes.as_map()
    }

    pub fn attribute(&self, attr_name: String) -> Option<String> {
        match &self.attributes {
            Attributes::UserDefined(map) => map.get(&attr_name).cloned(),
            Attributes::RoleOnly(role) if &attr_name == "role" => Some(role.to_string()),
            Attributes::RoleOnly(_) => None,
            Attributes::None => None,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    #[cfg(not(feature = "multi-user"))]
    pub fn is_allowed<A, R>(&self, _: A, _: R) -> KrillResult<bool> {
        // When not in multi-user mode we only have two states: authenticated or not authenticated (aka anonymous).
        // Only authenticated (i.e. not anonymous) actors are permitted to perform restricted actions, i.e. those for
        // which this fn is invoked.
        Ok(!self.is_anonymous())
    }

    #[cfg(feature = "multi-user")]
    pub fn is_allowed<A, R>(&self, action: A, resource: R) -> KrillResult<bool>
    where
        A: ToPolar + Display + Debug + Clone,
        R: ToPolar + Display + Debug + Clone,
    {
        if log_enabled!(log::Level::Trace) {
            trace!(
                "Access check: actor={}, action={}, resource={}",
                self.name(),
                &action,
                &resource
            );
        }

        if let Some(api_error) = &self.auth_error {
            trace!(
                "Authentication denied: actor={}, action={}, resource={}: {}",
                self.name(),
                &action,
                &resource,
                &api_error
            );
            return Err(Error::from(api_error.clone()));
        }

        match &self.policy {
            Some(policy) => match policy.is_allowed(self.clone(), action.clone(), resource.clone()) {
                Ok(allowed) => {
                    if log_enabled!(log::Level::Trace) {
                        trace!(
                            "Access {}: actor={:?}, action={:?}, resource={:?}",
                            if allowed { "granted" } else { "denied" },
                            self,
                            &action,
                            &resource
                        );
                    }
                    Ok(allowed)
                }
                Err(err) => {
                    error!(
                        "Access denied: actor={}, action={}, resource={}: {}",
                        self.name(),
                        &action,
                        &resource,
                        err
                    );
                    Ok(false)
                }
            },
            None => {
                // Auth policy is required, can only be omitted for use by test
                // rules inside an Oso policy. We should never get here, but we
                // don't want to crash Krill by calling unreachable!().
                error!(
                    "Unable to check access: actor={}, action={}, resource={}: {}",
                    self.name(),
                    &action,
                    &resource,
                    "Internal error: missing policy"
                );
                Ok(false)
            }
        }
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl fmt::Debug for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Actor(name={:?}, is_user={}, attr={:?})",
            self.name(),
            self.is_user,
            self.attributes
        )
    }
}
