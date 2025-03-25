//! Upgrading from versions before 0.10.0.

mod aspa;
mod migration;
mod old_events;
mod old_commands;

pub use self::migration::CasMigration;

