//! The options for the Trust Anchor client.

//------------ Sub-modules ---------------------------------------------------

pub mod proxy;
pub mod signer;

//------------ Content -------------------------------------------------------

use clap::Parser;


//------------ Command -------------------------------------------------------

#[derive(clap::Parser)]
#[command(version)]
pub enum Command {
    /// Manage the Trust Anchor Proxy
    Proxy(proxy::Command),

    /// Manage the Trust Anchor Signer
    Signer(signer::Command),
}

impl Command {
    /// Creates the options from the process arguments.
    ///
    /// If the arguments won’t result in usable options, exits the process.
    pub fn from_args() -> Self {
        Self::parse()
    }
}

