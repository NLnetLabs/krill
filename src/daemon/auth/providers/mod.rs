pub mod admin_token;

#[cfg(feature = "multi-user")]
pub mod config_file;
#[cfg(feature = "multi-user")]
pub mod openid_connect;

pub use admin_token::AdminTokenAuthProvider;

#[cfg(feature = "multi-user")]
pub use config_file::provider::ConfigFileAuthProvider;
#[cfg(feature = "multi-user")]
pub use openid_connect::provider::OpenIDConnectAuthProvider;
