//! Permissions and permission sets.
//!
//! This is a private module. Its public items are re-exported by the parent.

use std::{fmt, str};
use std::str::FromStr;
use serde::{Deserialize, Serialize};


//------------ Permission ----------------------------------------------------

macro_rules! define_permission {
    ( $( ($variant:ident, $text:expr), )* ) => {
        /// The set of available permissions.
        ///
        /// Each API request requires for the actor to have exactly one of these
        /// permissions.
        #[derive(Clone, Copy, Debug, Deserialize, Serialize)]
        #[repr(u32)]
        pub enum Permission {
            $(
                #[serde(rename = $text)]
                $variant,
            )*
        }

        impl Permission {
            pub fn iter() -> impl Iterator<Item = Self> {
                ALL_PERMISSIONS.iter().copied()
            }
        }

        impl str::FromStr for Permission {
            type Err = &'static str;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $( $text => Ok(Self::$variant), )*
                    _ => Err("unknown permission")
                }
            }
        }

        impl fmt::Display for Permission {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(
                    match *self {
                        $(
                            Self::$variant => ($text),
                        )*
                    }
                )
            }
        }

        const ALL_PERMISSIONS: &'static[Permission] = &[
            $( Permission::$variant, )*
        ];
    }
}

define_permission! {
    (Login, "login"),
    (PubAdmin, "pub-admin"),
    (PubList, "pub-list"),
    (PubRead, "pub-read"),
    (PubCreate, "pub-create"),
    (PubDelete, "pub-delete"),
    (CaList, "ca-list"),
    (CaRead, "ca-read"),
    (CaCreate, "ca-create"),
    (CaUpdate, "ca-update"),
    (CaAdmin, "ca-admin"),
    (CaDelete, "ca-delete"),
    (RoutesRead, "routes-read"),
    (RoutesUpdate, "routes-update"),
    (RoutesAnalysis, "routes-analysis"),
    (AspasRead, "aspas-read"),
    (AspasUpdate, "aspas-update"),
    (BgpsecRead, "bgpsec-read"),
    (BgpsecUpdate, "bgpsec-update"),
    (RtaList, "rta-list"),
    (RtaRead, "rta-read"),
    (RtaUpdate, "rta-update"),
}


//------------ ConfPermission ------------------------------------------------

/// A named permission as given in the config file.
///
/// This includes all the permissions themselves plus the three “glob”
/// permissions `"list"`, `"read"`, `"create"`, `"delete"`, and `"admin"`
/// which include all the respective permissions for all components.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(try_from = "&str")]
pub enum ConfPermission {
    Single(Permission),
    Any,
    Read,
    Update,
}

impl ConfPermission {
    fn add(self, set: PermissionSet) -> PermissionSet {
        let self_set = match self {
            Self::Single(perm) => {
                return set.add(perm)
            }
            Self::Any => PermissionSet::ANY,
            Self::Read => PermissionSet::CONF_READ,
            Self::Update => PermissionSet::CONF_UPDATE,
        };
        set.add_set(self_set)
    }
}

impl<'a> TryFrom<&'a str> for ConfPermission {
    type Error = String;

    fn try_from(src: &'a str) -> Result<Self, Self::Error> {
        if let Ok(res) = Permission::from_str(src) {
            return Ok(Self::Single(res))
        }

        match src {
            "any" => Ok(Self::Any),
            "read" => Ok(Self::Read),
            "update" => Ok(Self::Update),
            _ => Err(format!("unknown permission {src}"))
        }
    }
}


//------------ PermissionSet -------------------------------------------------

/// A set of permissions.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(from = "Vec<ConfPermission>")]
pub struct PermissionSet(u32);

impl PermissionSet {

    const fn mask(permission: Permission) -> u32 {
        1u32 << (permission as u32)
    }

    pub const fn add(self, permission: Permission) -> Self {
        Self(self.0 | Self::mask(permission))
    }

    pub const fn add_set(self, other: PermissionSet) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn remove(self, permission: Permission) -> Self {
        Self(self.0 & !Self::mask(permission))
    }

    pub fn has(self, permission: Permission) -> bool {
        self.0 & Self::mask(permission) != 0
    }

    pub fn iter(self) -> impl Iterator<Item = Permission> {
        Permission::iter().filter(move |perm| self.has(*perm))
    }

    const fn from_permissions(mut slice: &[Permission]) -> Self {
        let mut res = PermissionSet(0);
        while let Some((head, tail)) = slice.split_first() {
            res = res.add(*head);
            slice = tail;
        }
        res
    }
}

impl From<Vec<ConfPermission>> for PermissionSet {
    fn from(src: Vec<ConfPermission>) -> Self {
        let mut res = Self(0);
        for item in src {
            res = item.add(res)
        }
        res
    }
}


mod policy {
    use super::PermissionSet;
    use super::Permission::*;

    impl PermissionSet {
        pub const ANY: Self = Self(u32::MAX);

        pub const NONE: Self = Self(0);

        pub const READONLY: Self = Self::from_permissions(&[
            CaList,
            CaRead,
            PubList,
            PubRead,
            RoutesRead,
            RoutesAnalysis,
            AspasRead,
            BgpsecRead,
            RtaList,
            RtaRead
        ]);

        pub const READWRITE: Self = Self::from_permissions(&[
            CaList,
            CaRead,
            CaCreate,
            CaUpdate,
            PubList,
            PubRead,
            PubCreate,
            PubDelete,
            RoutesRead,
            RoutesAnalysis,
            RoutesUpdate,
            AspasRead,
            AspasUpdate,
            BgpsecRead,
            BgpsecUpdate,
            RtaList,
            RtaRead,
            RtaUpdate
        ]);

        pub const TESTBED: Self = Self::from_permissions(&[
            CaRead,
            CaUpdate,
            PubRead,
            PubCreate,
            PubDelete,
            PubAdmin
        ]);

        pub const CONF_READ: Self = Self::from_permissions(&[
            CaRead, RoutesRead, AspasRead, BgpsecRead, RtaRead,
        ]);

        pub const CONF_CREATE: Self = Self::from_permissions(&[
            CaCreate,
        ]);

        pub const CONF_UPDATE: Self = Self::from_permissions(&[
            RoutesUpdate, BgpsecUpdate, RtaUpdate,
        ]);

        pub const CONF_DELETE: Self = Self::from_permissions(&[
            PubDelete, CaDelete,
        ]);
    }
}

