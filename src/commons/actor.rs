use crate::{daemon::auth::Auth, commons::api::Handle};
use crate::daemon::auth::common::config::Role;
use crate::daemon::auth::Permissions;

#[derive(Clone, Eq, PartialEq)]
enum ActorName {
    AsStaticStr(&'static str),
    AsString(String),
}

#[derive(Clone)]
pub struct Actor {
    name: ActorName,
    is_user: bool,
    role: Option<Role>,
    included_cas: Vec<String>,
    excluded_cas: Vec<String>,
    new_auth: Option<Auth>,
}

impl Actor {
    pub const fn none() -> Actor {
        Actor {
            name: ActorName::AsStaticStr("none"),
            is_user: false,
            role: None,
            included_cas: vec![],
            excluded_cas: vec![],
            new_auth: None,
        }
    }

    pub const fn system(name: &'static str, role: Role) -> Actor {
        Actor {
            name: ActorName::AsStaticStr(name),
            is_user: false,
            role: Some(role),
            included_cas: vec![],
            excluded_cas: vec![],
            new_auth: None,
        }
    }

    /// Empty includes and empty excludes means grant access to all CAs.
    /// Otherwise a CA is only accessible if it is both NOT excluded AND is
    /// explicitly included.
    pub fn user(name: String, role: Option<Role>, inc: &[String], exc: &[String], new_auth: Option<Auth>) -> Actor {
        Actor {
            name: ActorName::AsString(name),
            is_user: true,
            role: role,
            included_cas: inc.to_vec(),
            excluded_cas: exc.to_vec(),
            new_auth: new_auth,
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

    pub fn name(&self) -> &str {
        match &self.name {
            ActorName::AsStaticStr(s) => s,
            ActorName::AsString(s) => s,
        }
    }

    pub fn role(&self) -> Option<Role> {
        self.role.clone()
    }

    pub fn has_permission(&self, wanted_permissions: Permissions) -> Option<bool> {
        if self.is_none() {
            return None
        }

        let entitled_perms = match self.role {
            Some(Role::Admin)        => Permissions::ALL_ADMIN,
            Some(Role::GuiReadOnly)  => Permissions::GUI_READ,
            Some(Role::GuiReadWrite) => Permissions::GUI_WRITE,
            Some(Role::Testbed)      => Permissions::TESTBED,
            None                     => Permissions::NONE,
        };

        Some(entitled_perms.contains(wanted_permissions))
    }

    pub fn can_access_ca(&self, ca: &Handle) -> bool {
        let ca = &ca.to_string();
        !self.excluded_cas.contains(ca) && (self.included_cas.is_empty() || self.included_cas.contains(ca))
    }
}