use std::{io::Read, str::FromStr, sync::Arc};

use oso::{Oso, PolarClass, PolarValue, ToPolar};

use crate::{
    commons::{
        actor::Actor,
        error::{Error, KrillIoError},
        KrillResult,
    },
    constants::{ACTOR_DEF_ADMIN_TOKEN, ACTOR_DEF_ANON, ACTOR_DEF_KRILL, ACTOR_DEF_TESTBED},
    daemon::{
        auth::{
            common::{permissions::Permission, NoResourceType},
            PolarHandle,
        },
        config::Config,
    },
};

#[derive(Clone)]
pub struct AuthPolicy {
    oso: Arc<Oso>,
}

impl std::ops::Deref for AuthPolicy {
    type Target = Arc<Oso>;

    fn deref(&self) -> &Self::Target {
        &self.oso
    }
}

impl AuthPolicy {
    pub fn new(config: Arc<Config>) -> KrillResult<Self> {
        let mut oso = Oso::new();
        oso.register_class(Actor::get_polar_class()).unwrap();
        oso.register_class(PolarHandle::get_polar_class()).unwrap();

        // Register both the Permission enum as a Polar class and its variants as Polar constants. The former is useful
        // for writing Polar rules that only match on actual Krill Permissions, not on arbitrary strings, e.g.
        // `allow(actor, action: Permission, resource)`. The latter is useful when writing rules that depend on a
        // specific permission, e.g. `if action = CA_READ`. Without the variants as constants we would have to create a
        // new Permission each time, converting from a string to the Permission type, e.g.
        // `action = new Permission("CA_READ")`.
        oso.register_class(Permission::get_polar_class()).unwrap();
        for permission in Permission::iter() {
            let name = format!("{}", permission);
            oso.register_constant(permission, &name).unwrap();
        }

        // Load built-in Polar authorization policy rules from embedded strings
        Self::load_internal_policy(&mut oso, include_bytes!("../../../defaults/roles.polar"), "roles")?;
        Self::load_internal_policy(&mut oso, include_bytes!("../../../defaults/rules.polar"), "rules")?;
        Self::load_internal_policy(&mut oso, include_bytes!("../../../defaults/aliases.polar"), "aliases")?;
        Self::load_internal_policy(&mut oso, include_bytes!("../../../defaults/rbac.polar"), "rbac")?;
        Self::load_internal_policy(&mut oso, include_bytes!("../../../defaults/abac.polar"), "abac")?;

        // Load additional policy rules from files optionally provided by the customer
        Self::load_user_policy(config, &mut oso)?;

        // Sanity check: Verify the roles assigned to the built-in actors are as
        // expected.
        debug!("Running Polar self checks");

        // The "krill" built-in actor is used to attribute internal actions by
        // Krill that were not directly triggered by a user. This user should
        // have the "admin" role.
        Self::exec_query(&mut oso, r#"actor_has_role(Actor.builtin("krill"), "admin")"#)?;

        // The "admin-token" built-in actor is used for logins using the admin
        // token (aka the "admin_token" set in the config file or via env var).
        // This actor should have the "admin" role.
        Self::exec_query(&mut oso, r#"actor_has_role(Actor.builtin("admin-token"), "admin")"#)?;

        // The built-in test actor "anon" represents a not-logged-in user and
        // as such lacks a role. We should be able to test that it the actor
        // does not have any role (represented by the _ placeholder in Oso Polar
        // syntax).
        Self::exec_query(&mut oso, r#"not actor_has_role(Actor.builtin("anon"), _)"#)?;

        // The built-in test actor "testbed" represents an anonymous user that
        // is using the testbed UI/API and is temporarily upgraded with the
        // necessary rights to perform the testbed related actions. These
        // actions are grouped into a "testbed" role. The "testbed" actor should
        // have the "testbed" role.
        Self::exec_query(&mut oso, r#"actor_has_role(Actor.builtin("testbed"), "testbed")"#)?;

        Ok(AuthPolicy { oso: Arc::new(oso) })
    }

    pub fn is_allowed<U, A, R>(&self, actor: U, action: A, resource: R) -> Result<bool, Error>
    where
        U: ToPolar,
        A: ToPolar,
        R: ToPolar,
    {
        self.oso
            .is_allowed(actor, action, resource)
            .map_err(|err| Error::custom(format!("Internal error while checking access against policy: {}", err)))
    }

    fn load_internal_policy(oso: &mut Oso, bytes: &[u8], fname: &str) -> KrillResult<()> {
        trace!("Loading Polar policy '{}'", fname);
        oso.load_str(
            std::str::from_utf8(bytes).map_err(|err| {
                Error::custom(format!("Internal Polar policy '{}' is not valid UTF-8: {}", fname, err))
            })?,
        )
        .map_err(|err| {
            Error::custom(format!(
                "Internal Polar policy '{}' is not valid Polar syntax: {}",
                fname, err
            ))
        })
    }

    fn exec_query(oso: &mut Oso, query: &str) -> KrillResult<()> {
        oso.query(query)
            .map_err(|err| Error::custom(format!("The Polar self check query '{}' failed: {}", query, err)))?;
        Ok(())
    }

    fn load_user_policy(config: Arc<Config>, oso: &mut Oso) -> KrillResult<()> {
        for policy in config.auth_policies.iter() {
            info!("Loading user-defined authorization policy file {:?}", policy);
            let fname = policy.file_name().unwrap().to_str().unwrap();
            let mut buffer = Vec::new();
            std::fs::File::open(policy.as_path())
                .map_err(|e| {
                    KrillIoError::new(format!("Could not open policy file '{}'", policy.to_string_lossy()), e)
                })?
                .read_to_end(&mut buffer)
                .map_err(|e| {
                    KrillIoError::new(format!("Could not read policy file '{}'", policy.to_string_lossy()), e)
                })?;
            AuthPolicy::load_internal_policy(oso, &buffer, fname)?;
        }

        Ok(())
    }
}

// Allow our "no resource" type to match the "nil" in Oso policy rules by making it convertible to the Rust type Oso
// uses when registering the nil constant. We can't use Option::<PolarValue>::None directly as it doesn't implement
// the Display trait which we depend on in non-trace level logging in `fn Actor::is_allowed()`.
//
// Note: for now it is not possible to use 'nil' directly due to https://github.com/osohq/oso/issues/788. Instead you
// have to do something like this:
//
//   allow(actor: Actor, action: Permission, _resource: Option) if
//       _resource = nil and
//       ...
//
// WHen the bug is fixed you should then be able to do this:
//
//   allow(actor: Actor, action: Permission, nil) if
//      ...
impl ToPolar for NoResourceType {
    #[allow(clippy::wrong_self_convention)]
    fn to_polar(self) -> oso::PolarValue {
        Option::<PolarValue>::None.to_polar()
    }
}

impl PolarClass for Actor {
    fn get_polar_class() -> oso::Class {
        Self::get_polar_class_builder()
            .set_constructor(Actor::test_from_details)
            .set_equality_check(|left: &Actor, right: &Actor| left.name() == right.name())
            .add_attribute_getter("name", |instance| instance.name().to_string())
            .add_class_method("builtin", |name: String| -> Actor {
                match name.as_str() {
                    "anon" => Actor::test_from_def(ACTOR_DEF_ANON),
                    "krill" => Actor::test_from_def(ACTOR_DEF_KRILL),
                    "admin-token" => Actor::test_from_def(ACTOR_DEF_ADMIN_TOKEN),
                    "testbed" => Actor::test_from_def(ACTOR_DEF_TESTBED),
                    _ => panic!("Unknown built-in actor name '{}'", name),
                }
            })
            // method to do a "contains" test, either get rid of this if the Oso
            // Polar "in" operator will suffice or move this to a separate Polar
            // Class called Util and name the method "contains".
            .add_class_method("is_in", |name: String, names: Vec<String>| -> bool {
                names.contains(&name)
            })
            .add_method("attr", Actor::attribute)
            .add_method("attrs", Actor::attributes)
            .build()
    }

    fn get_polar_class_builder() -> oso::ClassBuilder<Self> {
        oso::Class::builder()
    }
}

impl PolarClass for Permission {
    fn get_polar_class() -> oso::Class {
        Self::get_polar_class_builder()
            .set_constructor(|perm_name: String| -> Permission { Permission::from_str(&perm_name).unwrap() })
            .set_equality_check(|left: &Permission, right: &Permission| *left == *right)
            .build()
    }

    fn get_polar_class_builder() -> oso::ClassBuilder<Self> {
        oso::Class::builder()
    }
}

