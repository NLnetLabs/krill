use std::{
    borrow::Borrow,
    fmt::{Display, Formatter},
    ops::Deref,
    str::FromStr,
};

use crate::commons::storage::Scope;

/// A nonempty string that does not start or end with whitespace and does not
/// contain any instances of [`Scope::SEPARATOR`].
///
/// This is the owned variant of [`Segment`].
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct SegmentBuf(String);

impl SegmentBuf {
    pub fn parse_lossy(value: &str) -> Self {
        match Segment::parse(value) {
            Ok(segment) => segment.to_owned(),
            Err(error) => {
                let sanitized = value.trim().replace(Scope::SEPARATOR, "+");
                let nonempty = sanitized.is_empty().then(|| "EMPTY".to_owned()).unwrap_or(sanitized);
                let segment = Segment::parse(&nonempty).unwrap(); // cannot panic as all checks are performed above
                warn!("{value} is not a valid Segment: {error}\nusing {segment} instead");
                segment.to_owned()
            }
        }
    }

    pub fn concat(lhs: impl Into<SegmentBuf>, rhs: impl Into<SegmentBuf>) -> Self {
        Segment::parse(&format!("{}{}", lhs.into(), rhs.into()))
            .unwrap()
            .to_owned()
    }
}

impl AsRef<Segment> for SegmentBuf {
    fn as_ref(&self) -> &Segment {
        self
    }
}

impl Borrow<Segment> for SegmentBuf {
    fn borrow(&self) -> &Segment {
        self
    }
}

impl Deref for SegmentBuf {
    type Target = Segment;

    fn deref(&self) -> &Self::Target {
        unsafe { Segment::from_str_unchecked(&self.0) }
    }
}

impl Display for SegmentBuf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for SegmentBuf {
    type Err = ParseSegmentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Segment::parse(s)?.to_owned())
    }
}

impl From<&Segment> for SegmentBuf {
    fn from(value: &Segment) -> Self {
        value.to_owned()
    }
}

/// A nonempty string slice that does not start or end with whitespace and does
/// not contain any instances of [`Scope::SEPARATOR`].
///
/// For the owned variant, see [`SegmentBuf`].
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct Segment(str);

impl Segment {
    /// Parse a Segment from a string.
    ///
    /// # Errors
    /// If the string is empty, starts or ends with whitespace, or contains a
    /// [`Scope::SEPARATOR`] a [`ParseSegmentError`] variant will be returned.
    pub const fn parse(value: &str) -> Result<&Self, ParseSegmentError> {
        if value.is_empty() {
            Err(ParseSegmentError::Empty)
        } else {
            let bytes = value.as_bytes();
            if Self::leading_whitespace(bytes) || Self::trailing_whitespace(bytes) {
                Err(ParseSegmentError::TrailingWhitespace)
            } else if Self::contains_separator(bytes) {
                Err(ParseSegmentError::ContainsSeparator)
            } else {
                unsafe { Ok(Segment::from_str_unchecked(value)) }
            }
        }
    }

    /// Return the encapsulated string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Creates a Segment from a string without performing any checks.
    ///
    /// # Safety
    /// This should only be called for const values, where we know that
    /// the input is safe, or in case the input was thoroughly checked
    /// in another way.
    pub const unsafe fn from_str_unchecked(s: &str) -> &Self {
        &*(s as *const _ as *const Self)
    }

    const fn leading_whitespace(bytes: &[u8]) -> bool {
        matches!(bytes[0], 9 | 10 | 32)
    }

    const fn trailing_whitespace(bytes: &[u8]) -> bool {
        matches!(bytes[bytes.len() - 1], 9 | 10 | 32)
    }

    const fn contains_separator(bytes: &[u8]) -> bool {
        let mut index = 0;

        while index < bytes.len() {
            if bytes[index] == Scope::SEPARATOR as u8 {
                return true;
            }
            index += 1;
        }

        false
    }
}

impl Display for Segment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.0)
    }
}

impl ToOwned for Segment {
    type Owned = SegmentBuf;

    fn to_owned(&self) -> Self::Owned {
        SegmentBuf(self.0.to_owned())
    }
}

/// Represents all ways parsing a string as a [`Segment`] can fail.
#[derive(Debug)]
pub enum ParseSegmentError {
    TrailingWhitespace,
    Empty,
    ContainsSeparator,
}

impl Display for ParseSegmentError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseSegmentError::TrailingWhitespace => "segments must not start or end with whitespace",
            ParseSegmentError::Empty => "segments must be nonempty",
            ParseSegmentError::ContainsSeparator => "segments must not contain scope separators",
        }
        .fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::{Scope, Segment};

    #[test]
    fn test_trailing_separator_fails() {
        assert!(Segment::parse(&format!("test{}", Scope::SEPARATOR)).is_err());
    }

    #[test]
    fn test_trailing_space_fails() {
        assert!(Segment::parse("test ").is_err());
    }

    #[test]
    fn test_trailing_tab_fails() {
        assert!(Segment::parse("test\t").is_err());
    }

    #[test]
    fn test_trailing_newline_fails() {
        assert!(Segment::parse("test\n").is_err());
    }

    #[test]
    fn test_leading_separator_fails() {
        assert!(Segment::parse(&format!("{}test", Scope::SEPARATOR)).is_err());
    }

    #[test]
    fn test_leading_space_fails() {
        assert!(Segment::parse(" test").is_err());
    }

    #[test]
    fn test_leading_tab_fails() {
        assert!(Segment::parse("\ttest").is_err());
    }

    #[test]
    fn test_leading_newline_fails() {
        assert!(Segment::parse("\ntest").is_err());
    }

    #[test]
    fn test_containing_separator_fails() {
        assert!(Segment::parse(&format!("te{}st", Scope::SEPARATOR)).is_err());
    }

    #[test]
    fn test_containing_space_succeeds() {
        assert!(Segment::parse("te st").is_ok());
    }

    #[test]
    fn test_containing_tab_succeeds() {
        assert!(Segment::parse("te\tst").is_ok());
    }

    #[test]
    fn test_containing_newline_succeeds() {
        assert!(Segment::parse("te\nst").is_ok());
    }

    #[test]
    fn test_segment_succeeds() {
        assert!(Segment::parse("test").is_ok())
    }
}
