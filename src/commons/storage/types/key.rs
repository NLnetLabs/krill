//! The key of a stored value.

use std::{fmt, str};
use super::scope::Scope;
use super::segment::{ParseSegmentError, Segment, SegmentBuf};


//------------ Key -----------------------------------------------------------

/// The key of a stored value.
///
/// A key consists of a [`Scope`] and a *name* represented by a
/// [`SegmentBuf`].
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Key {
    scope: Scope,
    name: SegmentBuf,
}

impl Key {
    /// Create a key from both a scope and a name.
    pub fn new_scoped(scope: Scope, name: impl Into<SegmentBuf>) -> Key {
        Key {
            name: name.into(),
            scope,
        }
    }

    /// Create a key in the global scope.
    pub fn new_global(name: impl Into<SegmentBuf>) -> Key {
        Key::new_scoped(Scope::default(), name)
    }

    /// Returns a reference to the name of the key.
    pub fn name(&self) -> &Segment {
        &self.name
    }

    /// Returns a reference to the scope of the key.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Creates a new key in a subscope of the current scope.
    ///
    /// The returned key will use the same name. Its scope will have the
    /// given segment added to its end.
    pub fn with_sub_scope(&self, sub_scope: impl Into<SegmentBuf>) -> Self {
        let mut clone = self.clone();
        clone.add_sub_scope(sub_scope);
        clone
    }

    /// Adds a segment to the end of the scope of the key.
    pub fn add_sub_scope(&mut self, sub_scope: impl Into<SegmentBuf>) {
        self.scope.add_sub_scope(sub_scope);
    }

    /// Creates a new key in a super-scope of the current scope.
    ///
    /// The returned key will use the same name. Its scope will have the
    /// given segment added to its front.
    pub fn with_super_scope(
        &self, super_scope: impl Into<SegmentBuf>
    ) -> Self {
        let mut clone = self.clone();
        clone.add_super_scope(super_scope);
        clone
    }

    /// Adds a segment to the front of the scope of the key.
    pub fn add_super_scope(&mut self, super_scope: impl Into<SegmentBuf>) {
        self.scope.add_super_scope(super_scope);
    }
}


//--- FromStr

impl str::FromStr for Key {
    type Err = ParseSegmentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut segments: Vec<SegmentBuf> = s
            .split(Segment::SEPARATOR)
            .map(SegmentBuf::from_str)
            .collect::<Result<_, _>>()?;
        let name = segments.pop().unwrap();
        let scope = Scope::new(segments);

        Ok(Key { name, scope })
    }
}


//--- Display

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.scope.is_empty() {
            write!(f, "{}", self.name)
        } else {
            write!(f, "{}{}{}", self.scope, Segment::SEPARATOR, self.name)
        }
    }
}



