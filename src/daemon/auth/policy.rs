use std::fmt;
use std::collections::HashMap;
use std::sync::Arc;
use crate::commons::KrillResult;
use crate::commons::actor::Actor;
use crate::daemon::auth::Handle;
use crate::daemon::config::Config;


//------------ Role ----------------------------------------------------------

/// The role of actor has.
///
/// Permissions aren’t assigned to actors directly but rather to roles to
/// which actors are assigned in turn.
///
/// Most roles are defined through a string in configuration. However, there
/// are two special roles for anonymous actors and system actors.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Role(RoleEnum);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RoleEnum {
    /// The role used by system actors.
    System,

    /// The role used for anonymous users.
    Anonymous,

    /// A user role.
    User(Arc<str>)
}

impl Role {
    /// Creates a new user role with the given name.
    pub fn user(name: impl Into<Arc<str>>) -> Self {
        Self(RoleEnum::User(name.into().into()))
    }

    /// Creates a new system role.
    pub const fn system() -> Self {
        Self(RoleEnum::System)
    }

    /// Creates a new anonymous role.
    pub const fn anonymous() -> Self {
        Self(RoleEnum::Anonymous)
    }

    /// Returns whether the role is a user role.
    pub fn is_user(&self) -> bool {
        matches!(self.0, RoleEnum::User(_))
    }

    /// Returns whether the role is the system role.
    pub fn is_system(&self) -> bool {
        matches!(self.0, RoleEnum::System)
    }

    /// Returns whether the role is the anonymous role.
    pub fn is_anonymous(&self) -> bool {
        matches!(self.0, RoleEnum::Anonymous)
    }
}


//------------ Permission ----------------------------------------------------

/// The set of available permissions.
///
/// Each API request requires for the actor to have exactly one of these
/// permissions.
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)] // XXX Fix this
#[repr(u32)]
pub enum Permission {
    LOGIN = 0,
    PUB_ADMIN,
    PUB_LIST,
    PUB_READ,
    PUB_CREATE,
    PUB_DELETE,
    CA_LIST,
    CA_READ,
    CA_CREATE,
    CA_UPDATE,
    CA_ADMIN,
    CA_DELETE,
    ROUTES_READ,
    ROUTES_UPDATE,
    ROUTES_ANALYSIS,
    ASPAS_READ,
    ASPAS_UPDATE,
    ASPAS_ANALYSIS,
    BGPSEC_READ,
    BGPSEC_UPDATE,
    RTA_LIST,
    RTA_READ,
    RTA_UPDATE
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Permission::*;

        f.write_str(
            match *self {
                LOGIN => "LOGIN",
                PUB_ADMIN => "PUB_ADMIN",
                PUB_LIST => "PUB_LIST",
                PUB_READ => "PUB_READ",
                PUB_CREATE => "PUB_CREATE",
                PUB_DELETE => "PUB_DELETE",
                CA_LIST => "CA_LIST",
                CA_READ => "CA_READ",
                CA_CREATE => "CA_CREATE",
                CA_UPDATE => "CA_UPDATE",
                CA_ADMIN => "CA_ADMIN",
                CA_DELETE => "CA_DELETE",
                ROUTES_READ => "ROUTES_READ",
                ROUTES_UPDATE => "ROUTES_UPDATE",
                ROUTES_ANALYSIS => "ROUTES_ANALYSIS",
                ASPAS_READ => "ASPAS_READ",
                ASPAS_UPDATE => "ASPAS_UPDATE",
                ASPAS_ANALYSIS => "APSAS_ANALYSIS",
                BGPSEC_READ => "BGPSEC_READ",
                BGPSEC_UPDATE => "BGPSEC_UPDATE",
                RTA_LIST => "RTA_LIST",
                RTA_READ => "RTA_READ",
                RTA_UPDATE => "RTA_UPDATE",
            }
        )
    }
}


//------------ PermissionSet -------------------------------------------------

/// A set of permissions.
#[derive(Clone, Copy, Debug, Default)]
struct PermissionSet(u32);

impl PermissionSet {
    pub fn add(&mut self, permission: Permission) {
        self.0 |= 1u32.checked_shl(
            permission as u32
        ).expect("permission size overflow");
    }

    pub fn remove(&mut self, permission: Permission) {
        self.0 &= !(
            1u32.checked_shl(
                permission as u32
            ).expect("permission size overflow")
        );
    }

    pub fn has(&self, permission: Permission) -> bool {
        self.0 & (
            1u32.checked_shl(
                permission as u32
            ).expect("permission size overflow")
        ) != 0
    }
}


//------------ AuthPolicy ----------------------------------------------------

/// The policy allows checking for a permission on a resoure.
#[derive(Clone, Default)]
pub struct AuthPolicy {
    /// Permissions for requests without specific resources.
    none: PermissionSet,

    /// Blanket permission for all resources.
    ///
    /// This is checked for any resource that isn’t included in
    /// the `resources` field.
    any: PermissionSet,

    /// Permissions for specific resources.
    resources: HashMap<Handle, PermissionSet>,
}

impl AuthPolicy {
    pub fn new(_config: &Config) -> KrillResult<Self> {
        unimplemented!()
    }

    pub fn is_allowed(
        &self,
        permission: Permission,
        resource: Option<&Handle>
    ) -> bool {
        match resource {
            Some(resource) => {
                match self.resources.get(resource) {
                    Some(permissions) => permissions.has(permission),
                    None => self.any.has(permission),
                }
            }
            None => {
                self.none.has(permission)
            }
        }
    }
}


//------------ AuthPolicyMap -------------------------------------------------

/// A map providing the policy for each known actor.
#[derive(Clone, Default)]
pub struct AuthPolicyMap {
    map: HashMap<Arc<Actor>, Arc<AuthPolicy>>,

    default: Arc<AuthPolicy>,
}

impl AuthPolicyMap {
    pub fn new(_config: &Config) -> KrillResult<Self> {
        unimplemented!()
    }

    pub fn get_policy(&self, _actor: &Actor) -> Arc<AuthPolicy> {
        unimplemented!()
    }

    pub fn is_allowed(
        &self,
        _actor: &Actor,
        _permission: Permission,
        _resource: Option<&Handle>,
    ) -> bool {
        unimplemented!()
    }

    pub fn is_user_allowed(
        &self,
        _user_id: &str,
        _permission: Permission,
        _resource: Option<&Handle>,
    ) -> bool {
        unimplemented!()
    }
}

