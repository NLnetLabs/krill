use std::{
    io::Read,
    str::FromStr,
    sync::{Arc, Mutex},
};

use oso::{Oso, PolarClass, ToPolar};

use crate::{commons::{actor::Actor, api::Handle, error::Error, KrillResult}, constants::{ACTOR_DEF_ANON, ACTOR_DEF_KRILL, ACTOR_DEF_MASTER_TOKEN, ACTOR_DEF_TESTBED}, daemon::{auth::common::permissions::Permission, config::Config, http::RequestPath}};

/// Access to Oso is protected by a shareable mutex lock, as demonstrated in the
/// Oso Rust [getting started example](https://github.com/osohq/oso-rust-quickstart/blob/d469f7594b1d07e2203f5dc6e88d0435fef35468/src/server.rs#L50).
#[derive(Clone)]
pub struct AuthPolicy {
    oso: Arc<Mutex<Oso>>,
}

impl std::ops::Deref for AuthPolicy {
    type Target = Arc<Mutex<Oso>>;

    fn deref(&self) -> &Self::Target {
        &self.oso
    }
}

impl AuthPolicy {
    pub fn new(config: Arc<Config>) -> KrillResult<Self> {
        let mut oso = Oso::new();
        oso.register_class(Actor::get_polar_class()).unwrap();
        oso.register_class(Handle::get_polar_class()).unwrap();
        oso.register_class(Permission::get_polar_class()).unwrap();
        oso.register_class(RequestPath::get_polar_class()).unwrap();

        Self::load_internal_policy(&mut oso, include_bytes!("../../../defaults/roles.polar"), "roles")?;
        Self::load_internal_policy(&mut oso, include_bytes!("../../../defaults/rules.polar"), "rules")?;
        Self::load_internal_policy(&mut oso, include_bytes!("../../../defaults/aliases.polar"), "aliases")?;
        Self::load_internal_policy(&mut oso, include_bytes!("../../../defaults/rbac.polar"), "rbac")?;
        Self::load_internal_policy(&mut oso, include_bytes!("../../../defaults/abac.polar"), "abac")?;

        Self::load_user_policy(config, &mut oso)?;

        // Sanity check: Verify the roles assigned to the built-in actors are as
        // expected.
        debug!("Running Polar self checks");

        // The "krill" built-in actor is used to attribute internal actions by
        // Krill that were not directly triggered by a user. This user should
        // have the "admin" role.
        Self::exec_query(&mut oso, r#"actor_has_role(Actor.builtin("krill"), "admin")"#)?;

        // The "master-token" built-in actor is used for logins using the master
        // token (aka the "auth_token" set in the config file or via env var).
        // This actor should have the "admin" role.
        Self::exec_query(&mut oso, r#"actor_has_role(Actor.builtin("master-token"), "admin")"#)?;

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

        Ok(AuthPolicy {
            oso: Arc::new(Mutex::new(oso)),
        })
    }

    pub fn is_allowed<U, A, R>(&self, actor: U, action: A, resource: R) -> Result<bool, Error>
    where
        U: ToPolar,
        A: ToPolar,
        R: ToPolar,
    {
        match self.oso.lock() {
            Ok(mut oso) => oso
                .is_allowed(actor, action, resource)
                .map_err(|err| Error::custom(format!("Internal error while checking access against policy: {}", err))),
            Err(err) => Err(Error::custom(format!(
                "Internal error obtaining access policy lock: {}",
                err
            ))),
        }
    }

    fn load_internal_policy(oso: &mut Oso, bytes: &[u8], fname: &str) -> KrillResult<()> {
        trace!("Loading internal Polar policy '{}'", fname);
        oso.load_str(
            std::str::from_utf8(bytes)
                .map_err(|err| Error::custom(format!("Internal Polar policy '{}' is not valid UTF-8: {}", fname, err)))?,
        )
        .map_err(|err| Error::custom(format!("Internal Polar policy '{}' is not valid Polar syntax: {}", fname, err)))
    }

    fn exec_query(oso: &mut Oso, query: &str) -> KrillResult<()> {
        oso.query(query)
            .map_err(|err| Error::custom(format!("The Polar self check query '{}' failed: {}", query, err)))?;
        Ok(())
    }

    fn load_user_policy(config: Arc<Config>, oso: &mut Oso) -> KrillResult<()> {
        if config.auth_policy.is_file() {
            info!(
                "Loading user-defined authorization policy from file {:?}",
                &config.auth_policy
            );
            let fname = config.auth_policy.file_name().unwrap().to_str().unwrap();
            let mut buffer = Vec::new();
            std::fs::File::open(config.auth_policy.as_path())?.read_to_end(&mut buffer)?;
            AuthPolicy::load_internal_policy(oso, &buffer, fname)?;
        }

        Ok(())
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
                    "master-token" => Actor::test_from_def(ACTOR_DEF_MASTER_TOKEN),
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
            .build()
    }

    fn get_polar_class_builder() -> oso::ClassBuilder<Self> {
        oso::Class::builder()
    }
}

impl PolarClass for Handle {
    fn get_polar_class() -> oso::Class {
        Self::get_polar_class_builder()
            .set_constructor(|name: String| Handle::from_str(&name).unwrap())
            .set_equality_check(|left: &Handle, right: &Handle| left == right)
            .add_attribute_getter("name", |instance| instance.as_str().to_string())
            .build()
    }

    fn get_polar_class_builder() -> oso::ClassBuilder<Self> {
        oso::Class::builder()
    }
}

impl PolarClass for RequestPath {
    fn get_polar_class() -> oso::Class {
        Self::get_polar_class_builder()
            .add_attribute_getter("path", |instance| instance.full().to_string())
            .set_constructor(|path: String| -> RequestPath {
                RequestPath::from_request(&hyper::Request::builder().method("GET").uri(path).body(()).unwrap())
            })
            .build()
    }

    fn get_polar_class_builder() -> oso::ClassBuilder<Self> {
        oso::Class::builder()
    }
}

impl PolarClass for Permission {
    fn get_polar_class() -> oso::Class {
        Self::get_polar_class_builder()
            .set_constructor(|perm_name: String| -> Permission {
                Permission::from_str(&perm_name).unwrap()
            })
            .set_equality_check(|left: &Permission, right: &Permission| *left == *right)
            .build()
    }

    fn get_polar_class_builder() -> oso::ClassBuilder<Self> {
        oso::Class::builder()
    }
}