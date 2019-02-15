//! General utility modules for use all over the code base
use std::time::Duration;
use bytes::Bytes;
use chrono::DateTime;
use chrono::Utc;
use chrono::offset::TimeZone;
use rpki::crypto::DigestAlgorithm;
use serde::Serialize;
use serde::Serializer;
use serde::Deserializer;
use serde::Deserialize;

pub mod ext_serde;
pub mod file;
pub mod httpclient;
pub mod softsigner;
pub mod test;
pub mod xml;

pub fn sha256(object: &[u8]) -> Bytes {
    Bytes::from(DigestAlgorithm.digest(object).as_ref())
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Time(DateTime<Utc>);

impl Time {
    pub fn now() -> Self {
        Time(Utc::now())
    }

    pub fn before_now(dur: Duration) -> Self {
        let mut millis = Utc::now().timestamp_millis();
        millis -= dur.as_secs() as i64 * 1000;

        Time(Utc.timestamp_millis(millis))
    }

    pub fn on_or_before(&self, other: &Time) -> bool {
        self.0.timestamp_millis() <= other.0.timestamp_millis()
    }
}

impl Serialize for Time {
    fn serialize<S>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_i64(self.0.timestamp_millis())
    }
}

impl<'de> Deserialize<'de> for Time {
    fn deserialize<D>(
        deserializer: D
    ) -> Result<Self, D::Error> where D: Deserializer<'de> {

        let timestamp: i64 = i64::deserialize(deserializer)?;
        Ok(Time(Utc.timestamp_millis(timestamp)))
    }
}

