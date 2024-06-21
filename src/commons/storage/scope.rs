use std::{
    cmp,
    fmt::{Display, Formatter},
    iter::FromIterator,
    str::FromStr,
};

use crate::commons::storage::{ParseSegmentError, SegmentBuf};

/// Used to scope a [`Key`]. Consists of a vector of zero or more
/// [`SegmentBuf`]s.
///
/// [`Key`]: crate::Key
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "postgres", derive(postgres::types::ToSql, postgres::types::FromSql))]
pub struct Scope {
    segments: Vec<SegmentBuf>,
}

impl Scope {
    /// Character used to split on when parsing a Scope from a string.
    pub const SEPARATOR: char = '/';

    /// Create a `Scope` from a single [`Segment`].
    pub fn from_segment(segment: impl Into<SegmentBuf>) -> Self {
        Scope::new(vec![segment.into()])
    }

    /// Create an empty `Scope`.
    pub fn global() -> Self {
        Scope::new(Vec::new())
    }

    /// Create a `Scope` from a vector of [`SegmentBuf`]s.
    pub fn new(segments: Vec<SegmentBuf>) -> Self {
        Scope { segments }
    }

    /// Returns the underlying vector of [`SegmentBuf`]s.
    pub fn as_vec(&self) -> &Vec<SegmentBuf> {
        &self.segments
    }

    /// Returns the length of the underlying vector.
    pub fn len(&self) -> i32 {
        self.segments.len() as i32
    }

    ///  Returns `true` if the segment contains no elements.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Returns whether the underlying vector is empty.
    pub fn is_global(&self) -> bool {
        self.is_empty()
    }

    /// Two scopes match if the longest of the two contains all [`Segment`]s
    /// of the other.
    pub fn matches(&self, other: &Self) -> bool {
        let min_len = cmp::min(self.segments.len(), other.segments.len());
        self.segments[0..min_len] == other.segments[0..min_len]
    }

    /// Returns whether the encapsulated vector starts with a certain prefix.
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

    /// Create a new [`Scope`] and add a [`Segment`] to the end of it.
    pub fn with_sub_scope(&self, sub_scope: impl Into<SegmentBuf>) -> Self {
        let mut clone = self.clone();
        clone.add_sub_scope(sub_scope);
        clone
    }

    /// Add a [`Segment`] to the end of the scope.
    pub fn add_sub_scope(&mut self, sub_scope: impl Into<SegmentBuf>) {
        self.segments.push(sub_scope.into());
    }

    /// Create a new [`Scope`] and add a [`Segment`] to the front of it.
    pub fn with_super_scope(&self, super_scope: impl Into<SegmentBuf>) -> Self {
        let mut clone = self.clone();
        clone.add_super_scope(super_scope);
        clone
    }

    /// Add a [`Segment`] to the front of the scope.
    pub fn add_super_scope(&mut self, super_scope: impl Into<SegmentBuf>) {
        self.segments.insert(0, super_scope.into());
    }
}

impl Display for Scope {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.segments
                .iter()
                .map(|segment| segment.as_str())
                .collect::<Vec<_>>()
                .join(Self::SEPARATOR.encode_utf8(&mut [0; 4]))
        )
    }
}

impl FromStr for Scope {
    type Err = ParseSegmentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_suffix(Self::SEPARATOR).unwrap_or(s);
        let segments = s
            .split(Self::SEPARATOR)
            .map(SegmentBuf::from_str)
            .collect::<Result<_, _>>()?;
        Ok(Scope { segments })
    }
}

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

impl Extend<SegmentBuf> for Scope {
    fn extend<T: IntoIterator<Item = SegmentBuf>>(&mut self, iter: T) {
        self.segments.extend(iter)
    }
}

impl FromIterator<SegmentBuf> for Scope {
    fn from_iter<T: IntoIterator<Item = SegmentBuf>>(iter: T) -> Self {
        let segments = iter.into_iter().collect();
        Scope { segments }
    }
}

impl From<Vec<SegmentBuf>> for Scope {
    fn from(segments: Vec<SegmentBuf>) -> Self {
        Scope { segments }
    }
}

#[cfg(test)]
mod tests {
    use super::Scope;

    #[test]
    fn test_matches() {
        let full: Scope = format!("this{sep}is{sep}a{sep}beautiful{sep}scope", sep = Scope::SEPARATOR)
            .parse()
            .unwrap();
        let partial: Scope = format!("this{sep}is{sep}a", sep = Scope::SEPARATOR).parse().unwrap();
        let wrong: Scope = format!("this{sep}is{sep}b", sep = Scope::SEPARATOR).parse().unwrap();

        assert!(full.matches(&partial));
        assert!(partial.matches(&full));
        assert!(!partial.matches(&wrong));
        assert!(!wrong.matches(&partial));
        assert!(!full.matches(&wrong));
        assert!(!wrong.matches(&full));
    }

    #[test]
    fn test_starts_with() {
        let full: Scope = format!("this{sep}is{sep}a{sep}beautiful{sep}scope", sep = Scope::SEPARATOR)
            .parse()
            .unwrap();
        let partial: Scope = format!("this{sep}is{sep}a", sep = Scope::SEPARATOR).parse().unwrap();
        let wrong: Scope = format!("this{sep}is{sep}b", sep = Scope::SEPARATOR).parse().unwrap();

        assert!(full.starts_with(&partial));
        assert!(!partial.starts_with(&full));
        assert!(!partial.starts_with(&wrong));
        assert!(!wrong.starts_with(&partial));
        assert!(!full.starts_with(&wrong));
        assert!(!wrong.starts_with(&full));
    }
}
