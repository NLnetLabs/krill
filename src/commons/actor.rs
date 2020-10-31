use crate::commons::api::Handle;

#[derive(Clone)]
enum ActorName {
    AsStaticStr(&'static str),
    AsString(String),
}

#[derive(Clone)]
pub struct Actor {
    name: ActorName,
    is_user: bool,
    included_cas: Vec<String>,
    excluded_cas: Vec<String>,
}

impl Actor {
    pub const fn system(name: &'static str) -> Actor {
        Actor {
            name: ActorName::AsStaticStr(name),
            is_user: false,
            included_cas: vec![],
            excluded_cas: vec![],
        }
    }

    /// Empty includes and empty excludes means grant access to all CAs.
    /// Otherwise a CA is only accessible if it is both NOT excluded AND is
    /// explicitly included.
    pub fn user(name: String, inc: &[String], exc: &[String]) -> Actor {
        Actor {
            name: ActorName::AsString(name),
            is_user: true,
            included_cas: inc.to_vec(),
            excluded_cas: exc.to_vec(),
        }
    }

    pub fn is_user(&self) -> bool {
        self.is_user
    }

    pub fn name(&self) -> &str {
        match &self.name {
            ActorName::AsStaticStr(s) => s,
            ActorName::AsString(s) => s,
        }
    }

    pub fn can_access_ca(&self, ca: &Handle) -> bool {
        let ca = &ca.to_string();
        !self.excluded_cas.contains(ca) || self.included_cas.is_empty() || self.included_cas.contains(ca)
    }
}