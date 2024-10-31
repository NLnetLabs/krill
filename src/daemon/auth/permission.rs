use std::{fmt, str};
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
    (AspasAnalysis, "aspas-analyisis"),
    (BgpsecRead, "bgpsec-read"),
    (BgpsecUpdate, "bgpsec-update"),
    (RtaList, "rta-list"),
    (RtaRead, "rta-read"),
    (RtaUpdate, "rta-update"),
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
            CaList,
            CaRead,
            PubList,
            PubRead,
            RoutesRead,
            RoutesAnalysis,
            AspasRead,
            AspasAnalysis,
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
            AspasAnalysis,
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
    }
}

