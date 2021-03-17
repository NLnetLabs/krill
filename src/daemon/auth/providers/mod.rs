pub mod master_token;

#[cfg(feature = "multi-user")]
pub mod config_file;
#[cfg(feature = "multi-user")]
pub mod openid_connect;

pub use master_token::MasterTokenAuthProvider;

#[cfg(feature = "multi-user")]
pub use config_file::provider::ConfigFileAuthProvider;
#[cfg(feature = "multi-user")]
pub use openid_connect::provider::OpenIDConnectAuthProvider;
