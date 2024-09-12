//! All actions performed by Krill are authorized by and attributed to an
//! Actor.
//!
//! An Actor either represents Krill itself or an external client of Krill.
//! Actors can only be created by the
//! [Authorizer](crate::daemon::auth::Authorizer).
//!
//! An [ActorDef] defines an Actor that can be created later.
//!
//! ActorDefs allows special internal actors to be described once as Rust
//! constants and turned into actual Actors at the point where they are
//! needed.
//!
//! ActorDefs also allow
//! [AuthProvider](crate::daemon::auth::authorizer::AuthProvider)s
//! to define the Actor that should be created without needing any knowledge
//! of the Authorizer.

use std::fmt;
use std::sync::Arc;


//------------ Actor ---------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Actor(ActorName);

#[derive(Clone, Debug)]
enum ActorName {
    /// A system actor for the given component.
    System(&'static str),

    /// A user actor that has not been authenticated.
    Anonymous,

    /// A user actor with the provided user ID.
    User(Arc<str>)
}

impl Actor {
    /// Creates a system actor for the given component.
    pub const fn system(component: &'static str) -> Self {
        Self(ActorName::System(component))
    }

    /// Creates the anonymous actor.
    pub const fn anonymous() -> Self {
        Self(ActorName::Anonymous)
    }

    /// Creates a user actor with the given user ID.
    pub fn user(user_id: impl Into<Arc<str>>) -> Self {
        Self(ActorName::User(user_id.into()))
    }

    /// Returns whether the actor is a system actor.
    pub fn is_system(&self) -> bool {
        matches!(self.0, ActorName::System(_))
    }

    /// Returns whether the actor is the anonymous actor.
    pub fn is_anonymous(&self) -> bool {
        matches!(self.0, ActorName::Anonymous)
    }

    /// Returns whether the actor is a user actor.
    pub fn is_user(&self) -> bool {
        matches!(self.0, ActorName::User(_))
    }

    /// Returns the simple name of the actor.
    ///
    /// For system actors, this is the component name. For the anonymous
    /// actor, this is the string `"anonymous"`. For user actors, it is their
    /// user ID.
    pub fn name(&self) -> &str {
        match self.0 {
            ActorName::System(ref component) => component,
            ActorName::Anonymous => "anonymous",
            ActorName::User(ref user_id) => user_id.as_ref(),
        }
    }

    /// Returns the audit name of the actor.
    ///
    /// This is the name stored with each command. For system actors, this
    /// is the component name. For the anonymous actor, this is the string
    /// `"anonymous"`. For user actors, it is the user ID prefixed with
    /// `user:`.
    pub fn audit_name(&self) -> String {
        match self.0 {
            ActorName::System(ref component) => component.to_string(),
            ActorName::Anonymous => "anonymous".to_string(),
            ActorName::User(ref user_id) => {
                format!("user:{}", user_id.as_ref())
            }
        }
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.name())
    }
}




/*
use std::fmt;
use std::sync::Arc;

use crate::{
    commons::{
        error::{ApiAuthError, Error},
        KrillResult,
    },
    daemon::auth::{policy::{AuthPolicy, Permission}, Auth, Handle},
};

#[derive(Clone, Deserialize, Eq, PartialEq, Debug, Serialize)]
pub enum ActorName {
    AsString(String),
}

impl ActorName {
    pub fn as_str(&self) -> &str {
        match &self {
            ActorName::AsString(s) => s,
        }
    }
}

impl From<String> for ActorName {
    fn from(src: String) -> Self {
        Self::AsString(src)
    }
}

impl fmt::Display for ActorName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_str().fmt(f)
    }
}


#[derive(Clone, Debug)]
pub struct ActorDef {
    pub name: ActorName,
    pub new_auth: Option<Auth>,
    pub auth_error: Option<ApiAuthError>,
}

impl ActorDef {
    pub const fn anonymous() -> ActorDef {
        ActorDef {
            name: ActorName::AsStaticStr("anonymous"),
            new_auth: None,
            auth_error: None,
        }
    }

    pub const fn system(name: &'static str) -> ActorDef {
        ActorDef {
            name: ActorName::AsStaticStr(name),
            new_auth: None,
            auth_error: None,
        }
    }

    pub fn user(
        name: ActorName,
        new_auth: Option<Auth>,
    ) -> ActorDef {
        ActorDef {
            name,
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
    new_auth: Option<Auth>,
    policy: Arc<AuthPolicy>,

    #[cfg_attr(not(feature = "multi-user"), allow(dead_code))]
    auth_error: Option<ApiAuthError>,
}

impl PartialEq for Actor {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl PartialEq<ActorDef> for Actor {
    fn eq(&self, other: &ActorDef) -> bool {
        self.name == other.name
    }
}

impl Actor {
    /// Only for krillta
    ///
    /// No authorizer framework exists for krillta. It is designed as a
    /// CLI. Sysadmins should ensure that only trusted people can execute
    /// the CLI (and/or read / write its data).
    pub fn krillta() -> Actor {
        Self::actor_from_def(crate::constants::ACTOR_DEF_KRILLTA)
    }

    /// Setup a System Actor
    ///
    /// This is an admin user used by the system itself. Authorizer frameworks
    /// are not relevant to it.
    pub fn system_actor() -> Actor {
        Self::actor_from_def(crate::constants::ACTOR_DEF_KRILL)
    }

    /// Should only be used for system users, i.e. not for mapping
    /// logged in users.
    pub fn actor_from_def(_actor_def: ActorDef) -> Actor {
        unimplemented!()
        /*
        Actor {
            name: actor_def.name.clone(),
            new_auth: None,
            auth_error: None,
            policy: None,
        }
        */
    }

    /*
    /// Only for use in testing
    pub fn test_from_details(
        name: String,
        attrs: HashMap<String, String>,
    ) -> Actor {
        Actor {
            name: ActorName::AsString(name),
            attributes: Attributes::UserDefined(attrs),
            is_user: false,
            new_auth: None,
            auth_error: None,
            policy: None,
        }
    }
    */

    pub fn new(actor_def: ActorDef, policy: Arc<AuthPolicy>) -> Actor {
        Actor {
            name: actor_def.name.clone(),
            new_auth: actor_def.new_auth.clone(),
            auth_error: actor_def.auth_error,
            policy,
        }
    }

    pub fn is_user(&self) -> bool {
        unimplemented!()
    }

    pub fn is_anonymous(&self) -> bool {
        unimplemented!()
    }

    pub fn new_auth(&self) -> Option<Auth> {
        self.new_auth.clone()
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn is_allowed(
        &self,
        permission: Permission,
        resource: Option<&Handle>,
    ) -> KrillResult<bool> {
        trace!(
            "Access check: actor={}, permission={}, resource={:?}",
            self.name(), permission, resource
        );

        if let Some(api_error) = &self.auth_error {
            trace!(
                "Authentication denied: \
                 actor={}, permission={}, resource={:?}: {}",
                self.name(),
                permission,
                resource,
                api_error
            );
            return Err(Error::from(api_error.clone()));
        }

        let allowed = self.policy.is_allowed(permission, resource);
        trace!(
            "Access {}: actor={:?}, permission={:?}, \
             resource={:?}",
            if allowed { "granted" } else { "denied" },
            self,
            permission,
            resource
        );
        Ok(allowed)
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl fmt::Debug for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Actor(name={:?})", self.name())
    }
}
*/
