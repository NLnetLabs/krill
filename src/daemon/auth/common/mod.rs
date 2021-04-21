#[cfg(feature = "multi-user")]
pub mod crypt;

pub mod permissions;

#[derive(Debug, Clone)]
pub struct NoResourceType;
impl std::fmt::Display for NoResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<No Resource>")
    }
}

#[cfg(feature = "multi-user")]
pub mod session;
