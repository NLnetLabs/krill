//! RPKI Certificate Authority.

mod aspa;
mod bgpsec;
mod certauth;
mod child;
mod commands;
mod events;
mod keys;
mod manager;
mod parent;
pub mod publishing; // Temporary for ta.
mod rc;
mod roa;
mod rta;
mod status;
pub mod upgrades;

pub use self::manager::CaManager;
pub use self::manager::testbed_ca_handle;


// Temporary public re-exports for other modules. They should be refactored
// away.

pub use self::certauth::CertAuth;
pub use self::child::UsedKeyState;
pub use self::events::CertAuthEvent;
pub use self::keys::CertifiedKey;
pub use self::parent::Rfc8183Id;
pub use self::publishing::CaObjectsStore;
pub use self::rta::{
    ResourceTaggedAttestation, RtaContentRequest, RtaPrepareRequest,
};
pub use self::status::CaStatus;

