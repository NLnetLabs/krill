#[derive(Clone)]
enum ActorName {
    AsStaticStr(&'static str),
    AsString(String),
}

#[derive(Clone)]
pub struct Actor {
    name: ActorName,
}

impl Actor {
    pub const fn from_str(name: &'static str) -> Actor {
        Actor {
            name: ActorName::AsStaticStr(name)
        }
    }

    pub fn from_string(name: String) -> Actor {
        Actor {
            // ensure that dynamic actor names, i.e. those of an actual external
            // user, are distinguishable from internal hard-coded actor names
            // so that an end user cannot for example impersonate the internal
            // Krill user by setting their name to "krill" as with this code it
            // will end up in the log as "api:<krill>" instead of just plain
            // "krill".
            name: ActorName::AsString(format!("api:<{}>", name))
        }
    }

    pub fn new() -> Actor {
        Actor {
            name: ActorName::AsStaticStr("unknown")
        }
    }

    pub fn name(&self) -> &str {
        match &self.name {
            ActorName::AsStaticStr(s) => s,
            ActorName::AsString(s) => s,
        }
    }
}