use std::fmt;

use crate::commons::storage::Storable;

pub trait InitEvent: fmt::Display + Eq + PartialEq + Send + Sync + Storable + 'static {}
pub trait Event: fmt::Display + Eq + PartialEq + Send + Sync + Storable + 'static {}
