use std::collections::HashMap;
use std::sync::Arc;
use serde::Deserialize;
use crate::commons::error::ApiAuthError;
use super::{Handle, Permission, PermissionSet};


//------------ Role ----------------------------------------------------------

/// The role of actor has.
///
/// Permissions aren’t assigned to actors directly but rather to roles to
/// which actors are assigned in turn.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct Role {
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

impl Role {
    pub fn admin() -> Self {
        Self::simple(PermissionSet::ANY)
    }

    pub fn readwrite() -> Self {
        Self::simple(PermissionSet::READWRITE)
    }

    pub fn readonly() -> Self {
        Self::simple(PermissionSet::READONLY)
    }

    pub fn testbed() -> Self {
        Self::simple(PermissionSet::TESTBED)
    }

    pub fn anonymous() -> Self {
        Self::simple(PermissionSet::NONE)
    }

    pub fn simple(permissions: PermissionSet) -> Self {
        Self {
            none: permissions,
            any: permissions,
            resources: Default::default()
        }
    }

    pub fn with_resources(
        permissions: PermissionSet,
        resources: impl IntoIterator<Item = Handle>
    ) -> Self {
        Self {
            none: permissions,
            any: PermissionSet::NONE,
            resources: resources.into_iter().map(|handle| {
                (handle, permissions)
            }).collect()
        }
    }

    pub fn complex(
        none: PermissionSet,
        any: PermissionSet,
        resources: HashMap<Handle, PermissionSet>
    ) -> Self {
        Self { none, any, resources }
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
    permissions: PermissionSet,

    cas: Option<Vec<Handle>>,
}


//------------ RoleMap -------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RoleMap(HashMap<String, Arc<Role>>);

impl RoleMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(
        &mut self, name: impl Into<String>, role: impl Into<Arc<Role>>
    ) {
        self.0.insert(name.into(), role.into());
    }

    pub fn contains(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    pub fn get(&self, name: &str) -> Result<Arc<Role>, ApiAuthError> {
        self.0.get(name).cloned().ok_or_else(|| {
            ApiAuthError::ApiAuthPermanentError(
                "user with undefined role not caught by config check".into()
            )
        })
    }
}

