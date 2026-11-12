//! All the parts of the test environment.

pub use self::core::Environment;
pub use self::nginx::NginxServer;

pub mod core;
pub mod krill;
pub mod nginx;
pub mod routinator;
