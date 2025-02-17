//! The scope portion of a value address.

use std::{cmp, fmt, str};
use super::segment::{ParseSegmentError, Segment, SegmentBuf};


//------------ Scope ---------------------------------------------------------

/// The scope of a key.
///
/// A scope consists of a sequence of zero or more segments.
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Scope {
    segments: Vec<SegmentBuf>,
}

impl Scope {
    /// Create a new scope from a vec of segments.
    pub fn new(segments: Vec<SegmentBuf>) -> Self {
        Scope { segments }
    }

    /// Create an empty scope.
    pub fn global() -> Self {
        Scope::new(Vec::new())
    }
    /// Create a scope from a single segment.
    pub fn from_segment(segment: impl Into<SegmentBuf>) -> Self {
        Scope::new(vec![segment.into()])
    }

    /// Returns whether the scope is the global scope, ie., empty.
    pub fn is_global(&self) -> bool {
        self.segments.is_empty()
    }

    /// Returns the number of segments in the scope.
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Returns whether the scope is empty.
    ///
    /// This is identical to being global.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Returns the first segment of the scope of any.
    pub fn first_segment(&self) -> Option<&Segment> {
        self.segments.first().map(AsRef::as_ref)
    }

    /// Returns whether the scope matches some other scope.
    ///
    /// Two scopes match if the longest of the two contains all [`Segment`]s
    /// of the other.
    pub fn matches(&self, other: &Self) -> bool {
        let min_len = cmp::min(self.segments.len(), other.segments.len());
        self.segments[0..min_len] == other.segments[0..min_len]
    }

    /// Returns whether the scope starts with a certain prefix.
    pub fn starts_with(&self, prefix: &Self) -> bool {
        if prefix.segments.len() <= self.segments.len() {
            self.segments[0..prefix.segments.len()] == prefix.segments
        } else {
            false
        }
    }

    /// Returns a vector of all prefixes of the scope.
    pub fn sub_scopes(&self) -> Vec<Scope> {
        self.segments
            .iter()
            .scan(Scope::default(), |state, segment| {
                state.segments.push(segment.clone());
                Some(state.clone())
            })
            .collect()
    }

    /// Creates a new scope by add an Segment to the end of this scope.
    pub fn with_sub_scope(&self, sub_scope: impl Into<SegmentBuf>) -> Self {
        let mut clone = self.clone();
        clone.add_sub_scope(sub_scope);
        clone
    }

    /// Adds a segment to the end of the scope.
    pub fn add_sub_scope(&mut self, sub_scope: impl Into<SegmentBuf>) {
        self.segments.push(sub_scope.into());
    }

    /// Creates a new scope by add a segment to the front of this scope.
    pub fn with_super_scope(&self, super_scope: impl Into<SegmentBuf>) -> Self {
        let mut clone = self.clone();
        clone.add_super_scope(super_scope);
        clone
    }

    /// Adds a segment to the front of the scope.
    pub fn add_super_scope(&mut self, super_scope: impl Into<SegmentBuf>) {
        self.segments.insert(0, super_scope.into());
    }
}


//--- From, FromStr, FromIterator

impl str::FromStr for Scope {
    type Err = ParseSegmentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_suffix(Segment::SEPARATOR).unwrap_or(s);
        let segments = s
            .split(Segment::SEPARATOR)
            .map(SegmentBuf::from_str)
            .collect::<Result<_, _>>()?;
        Ok(Scope { segments })
    }
}

impl From<Vec<SegmentBuf>> for Scope {
    fn from(segments: Vec<SegmentBuf>) -> Self {
        Scope { segments }
    }
}

impl FromIterator<SegmentBuf> for Scope {
    fn from_iter<T: IntoIterator<Item = SegmentBuf>>(iter: T) -> Self {
        let segments = iter.into_iter().collect();
        Scope { segments }
    }
}


//--- Extend

impl Extend<SegmentBuf> for Scope {
    fn extend<T: IntoIterator<Item = SegmentBuf>>(&mut self, iter: T) {
        self.segments.extend(iter)
    }
}


//--- IntoIterator

impl IntoIterator for Scope {
    type IntoIter = <Vec<SegmentBuf> as IntoIterator>::IntoIter;
    type Item = <Vec<SegmentBuf> as IntoIterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.segments.into_iter()
    }
}

impl<'a> IntoIterator for &'a Scope {
    type IntoIter = <&'a Vec<SegmentBuf> as IntoIterator>::IntoIter;
    type Item = <&'a Vec<SegmentBuf> as IntoIterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.segments.iter()
    }
}


//--- Display

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.segments
                .iter()
                .map(|segment| segment.as_str())
                .collect::<Vec<_>>()
                .join(Segment::SEPARATOR.encode_utf8(&mut [0; 4]))
        )
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches() {
        let full: Scope = format!(
            "this{sep}is{sep}a{sep}beautiful{sep}scope",
            sep = Segment::SEPARATOR
        ).parse().unwrap();
        let partial: Scope = format!(
            "this{sep}is{sep}a", sep = Segment::SEPARATOR
        ).parse().unwrap();
        let wrong: Scope = format!(
            "this{sep}is{sep}b", sep = Segment::SEPARATOR
        ).parse().unwrap();

        assert!(full.matches(&partial));
        assert!(partial.matches(&full));
        assert!(!partial.matches(&wrong));
        assert!(!wrong.matches(&partial));
        assert!(!full.matches(&wrong));
        assert!(!wrong.matches(&full));
    }

    #[test]
    fn test_starts_with() {
        let full: Scope = format!(
            "this{sep}is{sep}a{sep}beautiful{sep}scope",
            sep = Segment::SEPARATOR
        ).parse().unwrap();
        let partial: Scope = format!(
            "this{sep}is{sep}a", sep = Segment::SEPARATOR
        ).parse().unwrap();
        let wrong: Scope = format!(
            "this{sep}is{sep}b", sep = Segment::SEPARATOR
        ).parse().unwrap();

        assert!(full.starts_with(&partial));
        assert!(!partial.starts_with(&full));
        assert!(!partial.starts_with(&wrong));
        assert!(!wrong.starts_with(&partial));
        assert!(!full.starts_with(&wrong));
        assert!(!wrong.starts_with(&full));
    }
}

