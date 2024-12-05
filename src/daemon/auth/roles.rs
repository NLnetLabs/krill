//! Roles and related types.
//!
//! This is a private module. Its public items are re-exported by the parent.

use std::collections::HashMap;
use std::sync::Arc;
use rpki::ca::idexchange::MyHandle;
use serde::Deserialize;
use super::{Permission, PermissionSet};


//------------ Role ----------------------------------------------------------

/// A set of access permissions for resources.
///
/// Roles provide an intermediary for assigning access permissions to users
/// by managing [permission sets][PermissionSet]. Separete sets can be
/// provided for specific resources, all other resources, and requests that
/// do not operate on resources.
///
/// Currently, roles are given names and are defined in
/// [Config::auth_roles][crate::daemon::config::Config::auth_roles] and
/// referenced by authorization providers through those names.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(from = "RoleConf")]
pub struct Role {
    /// Permissions for requests without specific resources.
    none: PermissionSet,

    /// Blanket permission for all resources.
    ///
    /// This is checked for any resource that isn’t included in
    /// the `resources` field.
    any: PermissionSet,

    /// Permissions for specific resources.
    resources: HashMap<MyHandle, PermissionSet>,
}

impl Role {
    /// Creates the special admin role.
    ///
    /// This role allows all access to everything.
    pub fn admin() -> Self {
        Self::simple(PermissionSet::ANY)
    }

    /// Creates the default read-write role.
    ///
    /// This role uses `PermissionSet::READWRITE` for everything.
    pub fn readwrite() -> Self {
        Self::simple(PermissionSet::READWRITE)
    }

    /// Creates the default read-only role.
    ///
    /// This role uses `PermissionSet::READONLY` for everything.
    pub fn readonly() -> Self {
        Self::simple(PermissionSet::READONLY)
    }

    /// Creates the special testbed role.
    ///
    /// This role uses `PermissionSet::TESTBED` for everything.
    pub fn testbed() -> Self {
        Self::simple(PermissionSet::TESTBED)
    }

    /// Creates the anonymous special role.
    ///
    /// This role allows nothing.
    pub fn anonymous() -> Self {
        Self::simple(PermissionSet::NONE)
    }

    /// Creates a role that uses the provided permission set for all access.
    pub fn simple(permissions: PermissionSet) -> Self {
        Self {
            none: permissions,
            any: permissions,
            resources: Default::default()
        }
    }

    /// Creates a role that uses the provided set for the given resources.
    ///
    /// The role will allow access with the set to non-resource requests and
    /// all resources provided. Access to all other resources will be denied.
    pub fn with_resources(
        permissions: PermissionSet,
        resources: impl IntoIterator<Item = MyHandle>
    ) -> Self {
        Self {
            none: permissions,
            any: PermissionSet::NONE,
            resources: resources.into_iter().map(|handle| {
                (handle, permissions)
            }).collect()
        }
    }

    /// Creates a comples role.
    ///
    /// The permission set `none` will be used for non-resource requests.
    /// The `resources` hash map contains special permission sets for the
    /// provided resources. The `any` set will be used for all resources
    /// not mentioned in the hash map.
    pub fn complex(
        none: PermissionSet,
        any: PermissionSet,
        resources: HashMap<MyHandle, PermissionSet>
    ) -> Self {
        Self { none, any, resources }
    }

    /// Returns whether access is allowed.
    ///
    /// The method whether the role allows access with the provided
    /// `permission` to the provided `resource`. If the resource is `None`,
    /// access for non-resource requests is checked.
    ///
    /// Returns `true` if access is allowed or `false` if not.
    pub fn is_allowed(
        &self,
        permission: Permission,
        resource: Option<&MyHandle>
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

impl From<RoleConf> for Role {
    fn from(src: RoleConf) -> Self {
        match src.cas {
            Some(cas) => Self::with_resources(src.permissions, cas),
            None => Self::simple(src.permissions)
        }
    }
}


//------------ RoleConf ------------------------------------------------------

/// The role definition used in the config file.
///
/// This currently only allows creation of a subset of the things that
/// [`Role`] supports. This is on purpose to keep the config format simple.
#[derive(Clone, Debug, Deserialize)]
struct RoleConf {
    /// The permission set to use.
    permissions: PermissionSet,

    /// An optional list of resources to limit access to.
    ///
    /// If this is `None`, access to all resources will be allowed.
    cas: Option<Vec<MyHandle>>,
}


//------------ RoleMap -------------------------------------------------------

/// A mapping storing roles under a name.
///
/// Roles are stored behind an arc to users to keep a keep of the role around.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct RoleMap(HashMap<String, Arc<Role>>);

impl RoleMap {
    /// Creates a new, empty role map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the given role.
    pub fn add(
        &mut self, name: impl Into<String>, role: impl Into<Arc<Role>>
    ) {
        self.0.insert(name.into(), role.into());
    }

    /// Returns whether the map contains a role by the given name.
    pub fn contains(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    /// Returns the role of the given name if present.
    pub fn get(&self, name: &str) -> Option<Arc<Role>> {
        self.0.get(name).cloned()
    }
}

