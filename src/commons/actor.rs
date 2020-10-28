pub struct Actor(&'static str);

impl Actor {
    pub const fn from_string(name: &'static str) -> Actor {
        Actor(name)
    }

    pub fn name(&self) -> &str {
        &self.0
    }
}