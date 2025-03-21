//! The entity initiating all actions in Krill.
//!
//! All actors are represented by the type [`Actor`] defined in this module.
//! An actor can be anonymous, a system actor representing Krill’s own
//! subsytems, or a user identified by the server’s
//! [`Authorizer`](crate::daemon::auth::Authorizer).

use std::fmt;
use std::sync::Arc;


//------------ Actor ---------------------------------------------------------

/// An entity intiating an action in Krill.
///
/// Every action performed by Krill are attributed to an actor. This type
/// represents such an actor.
///
/// There are three types of actors, each created through a dedicated
/// associated function:
///
/// * an anonymous actor, created via [`Actor::anonymous`], is used in cases
///   where a request could not be authenticated;
/// * a system actor, created via [`Actor::system`], represents a named
///   component of Krill itself; and
/// * a user, created via [`Actor::user`], represent an authenticated user.
///
/// A value of the `Actor` does not make any claims about the authenticity of
/// the actor it represents. It is thus primarily used to print or store the
/// name of an actor.
///
/// Values of this type can be cloned relatively cheaply. At worst, they
/// contain an arced reference to an allocated string.
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

