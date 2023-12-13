use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

use crate::commons::storage::{ParseSegmentError, Scope, Segment, SegmentBuf};

/// Represents the key used in KVx. Consists of a `scope` of type [`Scope`] and
/// a `name` of type [`SegmentBuf`].
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Key {
    scope: Scope,
    name: SegmentBuf,
}

impl Key {
    /// Create a `Key` from a [`Scope`] and a [`Segment`].
    pub fn new_scoped(scope: Scope, name: impl Into<SegmentBuf>) -> Key {
        Key {
            name: name.into(),
            scope,
        }
    }

    /// Create a `Key` from a [`Segment`].
    pub fn new_global(name: impl Into<SegmentBuf>) -> Key {
        Key::new_scoped(Scope::default(), name)
    }

    /// Returns the name of a `Key` (without its scope).
    pub fn name(&self) -> &Segment {
        &self.name
    }

    /// Returns the scope of a `Key` (without its name).
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Create a new [`Key`] and add a [`Segment`] to the end of its scope.
    pub fn with_sub_scope(&self, sub_scope: impl Into<SegmentBuf>) -> Self {
        let mut clone = self.clone();
        clone.add_sub_scope(sub_scope);
        clone
    }

    /// Add a [`Segment`] to the end of the scope of the key.
    pub fn add_sub_scope(&mut self, sub_scope: impl Into<SegmentBuf>) {
        self.scope.add_sub_scope(sub_scope);
    }

    /// Create a new [`Key`] and add a [`Segment`] to the front of its scope.
    pub fn with_super_scope(&self, super_scope: impl Into<SegmentBuf>) -> Self {
        let mut clone = self.clone();
        clone.add_super_scope(super_scope);
        clone
    }

    /// Add a [`Segment`] to the front of the scope of the key.
    pub fn add_super_scope(&mut self, super_scope: impl Into<SegmentBuf>) {
        self.scope.add_super_scope(super_scope);
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.scope.is_global() {
            write!(f, "{}", self.name)
        } else {
            write!(f, "{}{}{}", self.scope, Scope::SEPARATOR, self.name)
        }
    }
}

impl FromStr for Key {
    type Err = ParseSegmentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut segments: Vec<SegmentBuf> = s
            .split(Scope::SEPARATOR)
            .map(SegmentBuf::from_str)
            .collect::<Result<_, _>>()?;
        let name = segments.pop().unwrap();
        let scope = Scope::new(segments);

        Ok(Key { name, scope })
    }
}
