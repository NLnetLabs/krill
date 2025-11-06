//! The analyser for checking and suggesting ROAs.
//!
//! The analyser, [`BgpAnalyser`], downloads RISwhois dumps which contain
//! prefixes and origins seen in real BGP data by RIS and stores them in
//! memory. Based on this data, it checks whether the ROAs for a given CA
//! reflect what is seen by RIS and can make suggestions which ROAs should
//! be created.

pub use self::analyser::BgpAnalyser;
pub use self::riswhois::RisWhoisError;

mod analyser;
mod riswhois;

