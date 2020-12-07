#[cfg(feature = "multi-user")]
use oso::ToPolar;
#[cfg(feature = "multi-user")]
use std::fmt::Display;

use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;

use crate::daemon::auth::Auth;
use crate::daemon::auth::policy::AuthPolicy;

#[derive(Clone, Eq, PartialEq)]
enum ActorName {
    AsStaticStr(&'static str),
    AsString(String),
}

#[derive(Clone, Debug)]
pub enum Attributes {
    None,
    RoleOnly(&'static str),
    UserDefined(HashMap<String, String>)
}

#[derive(Clone)]
pub struct Actor {
    name: ActorName,
    is_user: bool,
    attributes: Attributes,
    new_auth: Option<Auth>,
    policy: Option<AuthPolicy>
}

impl Actor {
    pub const fn none() -> Actor {
        Actor {
            name: ActorName::AsStaticStr("none"),
            is_user: false,
            attributes: Attributes::None,
            new_auth: None,
            policy: None
        }
    }

    pub const fn system(name: &'static str, role: &'static str) -> Actor {
        Actor {
            name: ActorName::AsStaticStr(name),
            is_user: false,
            attributes: Attributes::RoleOnly(role),
            new_auth: None,
            policy: None
        }
    }

    /// Empty includes and empty excludes means grant access to all CAs.
    /// Otherwise a CA is only accessible if it is both NOT excluded AND is
    /// explicitly included.
    pub fn user(name: String, attributes: &HashMap<String, String>, new_auth: Option<Auth>) -> Actor {
        Actor {
            name: ActorName::AsString(name),
            is_user: true,
            attributes: Attributes::UserDefined(attributes.clone()),
            new_auth,
            policy: None
        }
    }

    pub fn is_user(&self) -> bool {
        self.is_user
    }

    pub fn is_none(&self) -> bool {
        self.name == ActorName::AsStaticStr("none")
    }

    pub fn new_auth(&self) -> Option<Auth> {
        self.new_auth.clone()
    }

    pub fn attributes(&self) -> HashMap<String, String> {
        match &self.attributes {
            Attributes::UserDefined(map) => map.clone(),
            Attributes::RoleOnly(role) => {
                let mut map = HashMap::new();
                map.insert("role".to_string(), role.to_string());
                map
            },
            Attributes::None => HashMap::new()
        }
    }

    pub fn attr(&self, attr_name: String) -> Option<String> {
        match &self.attributes {
            Attributes::UserDefined(map)                       => map.get(&attr_name).cloned(),
            Attributes::RoleOnly(role) if &attr_name == "role" => Some(role.to_string()),
            Attributes::RoleOnly(_)                            => None,
            Attributes::None                                   => None,
        }
    }

    pub fn name(&self) -> &str {
        match &self.name {
            ActorName::AsStaticStr(s) => s,
            ActorName::AsString(s) => s,
        }
    }

    #[cfg(not(feature = "multi-user"))]
    pub fn is_allowed<A, R>(&self, _: A, _: R) -> bool {
        true
    }

    #[cfg(feature = "multi-user")]
    pub fn is_allowed<A, R>(&self, action: A, resource: R)
         -> bool
    where
        A: ToPolar + Display + Clone,
        R: ToPolar + Display + Clone,
    {
        match &self.policy {
            Some(policy) => {
                match policy.lock() {
                    Ok(mut policy) => {
                        match policy.is_allowed(self.clone(), action.clone(), resource.clone()) {
                            Ok(allowed) => {
                                if log_enabled!(log::Level::Trace) {
                                    if allowed {
                                        trace!("Access granted: actor={}, action={}, resource={}",
                                            self.name(), &action, &resource);
                                    } else {
                                        trace!("Access denied: actor={:?}, action={}, resource={}",
                                            self, &action, &resource);
                                    }
                                }
                                allowed
                            },
                            Err(err) => {
                                error!("Unable to check access: actor={}, action={}, resource={}: {}",
                                    self.name(), &action, &resource, err);
                                false
                            }
                        }
                    },
                    Err(err) => {
                        error!("Unable to check access: actor={}, action={}, resource={}: {}",
                            self.name(), &action, &resource, err);
                        false
                    }
                }
            },
            None => {
                warn!("Unable to check access: actor={}, action={}, resource={}: {}",
                    self.name(), &action, &resource, "No policy defined");
                false
            }
        }
    }

    pub fn set_policy(&mut self, policy: AuthPolicy) {
        self.policy = Some(policy);
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl fmt::Debug for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Actor(name={:?}, is_user={}, attr={:?})",
            self.name(), self.is_user, self.attributes)
    }
}