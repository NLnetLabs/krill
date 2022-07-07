// Based on https://github.com/rust-lang/rfcs/issues/284#issuecomment-277871931
// Use a macro to build the Permission enum so that we can iterate over the enum variants when adding them as Polar
// constants in struct AuthPolicy. This ensures that we don't accidentally miss one. We can also implement the Display
// trait that we need Actor::is_allowed() and the FromStr trait and avoid labour intensive and error prone duplication
// of the enum variants that would be needed when implementing the traits manually.
macro_rules! iterable_enum {
    ($name:ident { $($variant:ident),* })   => (
        #[allow(non_camel_case_types)]
        #[derive(Clone, Debug, PartialEq)]
        pub enum $name { $($variant),* }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $( Self::$variant => write!(f, stringify!($variant)) ),+
                }
            }
        }

        impl std::str::FromStr for $name {
            type Err = String;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                match input {
                    $( stringify!($variant) => { Ok($name::$variant) }
                    ),+
                    _ => Err(format!("Unknown {} '{}'", stringify!($name), input))
                }
            }
        }

        impl $name {
            pub fn iter() -> Iter {
                Iter(None)
            }
        }

        pub struct Iter(Option<$name>);

        impl Iterator for Iter {
            type Item = $name;

            fn next(&mut self) -> Option<Self::Item> {
                match self.0 {
                    None                  => $( { self.0 = Some($name::$variant); Some($name::$variant) },
                    Some($name::$variant) => )* None,
                }
            }
        }
    );
}

iterable_enum! {
    Permission {
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
        RTA_UPDATE
    }
}
