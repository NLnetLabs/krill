pub mod master_token;

#[cfg(feature = "multi-user")]
pub mod openid_connect;
#[cfg(feature = "multi-user")]
pub mod config_file;

pub use master_token::MasterTokenAuthProvider;

#[cfg(feature = "multi-user")]
pub use openid_connect::provider::OpenIDConnectAuthProvider;
#[cfg(feature = "multi-user")]
pub use config_file::provider::ConfigFileAuthProvider;