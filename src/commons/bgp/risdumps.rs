//! Support parsing announcements in RIS Dumps
//!
//! http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz

use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::num::ParseIntError;
use std::path::PathBuf;
use std::str::FromStr;

use crate::commons::api::{AsNumber, AuthorizationFmtError, TypedPrefix};
use crate::commons::bgp::{Announcement, Announcements, TypedPrefixTreeBuilder};

fn parse_ris_file(
    builder: &mut TypedPrefixTreeBuilder<Announcement>,
    path: &PathBuf,
) -> Result<(), Error> {
    let file = File::open(path).map_err(|_| Error::read_error(path))?;
    let reader = BufReader::new(file);
    for lres in reader.lines() {
        let line = lres.map_err(Error::parse_error)?;
        if line.is_empty() || line.starts_with('%') {
            continue;
        }

        let mut values = line.split_whitespace();

        let asn_str = values.next().ok_or(Error::MissingColumn)?;
        let prefix_str = values.next().ok_or(Error::MissingColumn)?;
        let peers = values.next().ok_or(Error::MissingColumn)?;

        if u32::from_str(peers)? <= 5 {
            continue;
        }

        if asn_str.contains('{') {
            continue; // assets not supported (not important here either)
        }

        let asn = AsNumber::from_str(asn_str)?;
        let prefix = TypedPrefix::from_str(prefix_str)?;

        let ann = Announcement::new(asn, prefix);
        builder.add(ann);
    }
    Ok(())
}

pub fn parse_risdumps(paths: &[PathBuf]) -> Result<Announcements, Error> {
    let mut builder = TypedPrefixTreeBuilder::default();

    for path in paths {
        parse_ris_file(&mut builder, path)?;
    }

    Ok(Announcements::new(builder.build()))
}

//------------ Error --------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Cannot read file: {}", _0)]
    CannotRead(String),

    #[display(fmt = "Missing column in announcements input")]
    MissingColumn,

    #[display(fmt = "Error parsing announcements: {}", _0)]
    ParseError(String),
}

impl Error {
    fn read_error(path: &PathBuf) -> Self {
        Error::CannotRead(path.to_string_lossy().to_string())
    }
    fn parse_error(e: impl fmt::Display) -> Self {
        Error::ParseError(format!("{}", e))
    }
}

impl From<AuthorizationFmtError> for Error {
    fn from(e: AuthorizationFmtError) -> Self {
        Self::parse_error(e)
    }
}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self {
        Error::parse_error(e)
    }
}
