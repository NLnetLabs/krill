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
        match &self.0 {
            ActorName::System(component) => component,
            ActorName::Anonymous => "anonymous",
            ActorName::User(user_id) => user_id.as_ref(),
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

