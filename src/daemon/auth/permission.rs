use std::fmt;
use serde::{Deserialize, Serialize};


//------------ Permission ----------------------------------------------------

macro_rules! define_permission {
    ( $( $variant:ident, )* ) => {
        /// The set of available permissions.
        ///
        /// Each API request requires for the actor to have exactly one of these
        /// permissions.
        #[derive(Clone, Copy, Debug, Deserialize, Serialize)]
        #[allow(non_camel_case_types)] // XXX Fix this
        #[repr(u32)]
        pub enum Permission {
            $( $variant, )*
        }

        impl Permission {
            pub fn iter() -> impl Iterator<Item = Self> {
                ALL_PERMISSIONS.iter().copied()
            }
        }

        impl fmt::Display for Permission {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(
                    match *self {
                        $(
                            Self::$variant => stringify!($variant),
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
    LOGIN,
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
    RTA_UPDATE,
}


//------------ PermissionSet -------------------------------------------------

/// A set of permissions.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(from = "Vec<Permission>", into = "Vec<Permission>")]
pub struct PermissionSet(u32);

impl PermissionSet {

    const fn mask(permission: Permission) -> u32 {
        1u32 << (permission as u32)
    }

    pub const fn add(self, permission: Permission) -> Self {
        Self(self.0 | Self::mask(permission))
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

impl From<Vec<Permission>> for PermissionSet {
    fn from(src: Vec<Permission>) -> Self {
        let mut res = Self(0);
        for item in src {
            res = res.add(item)
        }
        res
    }
}

impl From<PermissionSet> for Vec<Permission> {
    fn from(src: PermissionSet) -> Self {
        src.iter().collect()
    }
}


mod policy {
    use super::PermissionSet;
    use super::Permission::*;

    impl PermissionSet {
        pub const ANY: Self = Self(u32::MAX);

        pub const NONE: Self = Self(0);

        pub const READONLY: Self = Self::from_permissions(&[
            CA_LIST,
            CA_READ,
            PUB_LIST,
            PUB_READ,
            ROUTES_READ,
            ROUTES_ANALYSIS,
            ASPAS_READ,
            ASPAS_ANALYSIS,
            BGPSEC_READ,
            RTA_LIST,
            RTA_READ
        ]);

        pub const READWRITE: Self = Self::from_permissions(&[
            CA_LIST,
            CA_READ,
            CA_CREATE,
            CA_UPDATE,
            PUB_LIST,
            PUB_READ,
            PUB_CREATE,
            PUB_DELETE,
            ROUTES_READ,
            ROUTES_ANALYSIS,
            ROUTES_UPDATE,
            ASPAS_READ,
            ASPAS_UPDATE,
            ASPAS_ANALYSIS,
            BGPSEC_READ,
            BGPSEC_UPDATE,
            RTA_LIST,
            RTA_READ,
            RTA_UPDATE
        ]);

        pub const TESTBED: Self = Self::from_permissions(&[
            CA_READ,
            CA_UPDATE,
            PUB_READ,
            PUB_CREATE,
            PUB_DELETE,
            PUB_ADMIN
        ]);
    }
}

