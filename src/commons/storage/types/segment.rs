//! Address segments.

use std::{borrow, error, fmt, mem, ops, str};


//------------ SegmentBuf ----------------------------------------------------

/// An owned address segment.
///
/// This is a non-empty string that does not contain the segment separator.
///
/// This is the owned variant of [`Segment`]
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct SegmentBuf(String);


//--- FromStr, TryFrom, From

impl str::FromStr for SegmentBuf {
    type Err = ParseSegmentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Segment::parse(s)?.to_owned())
    }
}

impl TryFrom<String> for SegmentBuf {
    type Error = ParseSegmentError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let _ = Segment::parse(s.as_str())?;
        Ok(Self(s))
    }
}

impl From<&Segment> for SegmentBuf {
    fn from(value: &Segment) -> Self {
        value.to_owned()
    }
}


//--- Deref, AsRef, Borrow

impl ops::Deref for SegmentBuf {
    type Target = Segment;

    fn deref(&self) -> &Self::Target {
        unsafe { Segment::from_str_unchecked(&self.0) }
    }
}
impl AsRef<Segment> for SegmentBuf {
    fn as_ref(&self) -> &Segment {
        self
    }
}

impl borrow::Borrow<Segment> for SegmentBuf {
    fn borrow(&self) -> &Segment {
        self
    }
}


//--- Display

impl fmt::Display for SegmentBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}


//------------ Segment -------------------------------------------------------

/// A slice of an address segment.
///
/// This is a non-empty string slice that does not contain the segment
/// separator.
///
/// For the owned variant, see [`SegmentBuf`]
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct Segment(str);

impl Segment {
    /// The segment separator character.
    ///
    /// This character will never appear inside a segment.
    pub const SEPARATOR: char = '/';

    /// Parses a segment from a string slice.
    ///
    /// The function fails if the string is empty, starts or ends with
    /// whitespace, or contains the [`Segment::SEPARATOR`].
    pub const fn parse(value: &str) -> Result<&Self, ParseSegmentError> {
        let mut bytes = value.as_bytes();

        if bytes.is_empty() {
            return Err(ParseSegmentError(ParseErrorEnum::Empty));
        }

        if bytes[0].is_ascii_whitespace() {
            return Err(
                ParseSegmentError(ParseErrorEnum::LeadingWhitespace)
            )
        }

        if bytes[bytes.len() - 1].is_ascii_whitespace() {
            return Err(
                ParseSegmentError(ParseErrorEnum::TrailingWhitespace)
            )
        }

        while let Some((head, tail)) = bytes.split_first() {
            if *head == Self::SEPARATOR as u8 {
                return Err(
                    ParseSegmentError(ParseErrorEnum::ContainsSeparator)
                )
            }
            bytes = tail;
        }

        Ok(unsafe { Self::from_str_unchecked(value) })
    }

    /// Parses a string and converts into a valid segment.
    ///
    /// Any occurences of `'/'` are replaced with `'+'` and an empty slice
    /// is replaced by `EMPTY`.
    ///
    /// Because this leads to potential name collisions, use of this function
    /// is strongly discouraged.
    //
    //  XXX Remove this function. This needs some migration code, though.
    pub fn parse_lossy(value: &str) -> SegmentBuf {
        match Segment::parse(value) {
            Ok(segment) => segment.to_owned(),
            Err(error) => {
                let sanitized = value.trim().replace(Segment::SEPARATOR, "+");
                let nonempty = sanitized
                    .is_empty()
                    .then(|| "EMPTY".to_owned())
                    .unwrap_or(sanitized);
                let segment = SegmentBuf(nonempty);
                warn!(
                    "{value} is not a valid Segment: {error}\n\
                     using {segment} instead"
                );
                segment
            }
        }
    }

    /// Creates a segment from the given slice or panics.
    ///
    /// This function should be used to create segment constants.
    pub const fn make(s: &str) -> &Self {
        match Segment::parse(s) {
            Ok(some) => some,
            Err(_) => panic!("invalid segment identifier")
        }
    }

    /// Creates a segment from a string slice without checking.
    ///
    /// # Safety
    ///
    /// The string slice must not be empty, must not start or end with ASCII
    /// white space and must not contain `Self::SEPARATOR`.
    pub const unsafe fn from_str_unchecked(s: &str) -> &Self {
        // SAFETY: Self has #repr(transparent)
        mem::transmute(s)
    }

    /// Returns a string slice of the segment.
    pub const fn as_str(&self) -> &str {
        &self.0
    }
}


//--- TryFrom

impl<'a> TryFrom<&'a str> for &'a Segment {
    type Error = ParseSegmentError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Segment::parse(s)
    }
}


//--- ToOwned

impl ToOwned for Segment {
    type Owned = SegmentBuf;

    fn to_owned(&self) -> Self::Owned {
        SegmentBuf(self.0.to_owned())
    }
}


//--- Display

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}



//------------ ParseSegmentError ---------------------------------------------

/// An error happened while parsing a string into a [`Segment`].
#[derive(Clone, Copy, Debug)]
pub struct ParseSegmentError(ParseErrorEnum);

#[derive(Clone, Copy, Debug)]
enum ParseErrorEnum {
    Empty,
    LeadingWhitespace,
    TrailingWhitespace,
    ContainsSeparator,
}

impl fmt::Display for ParseSegmentError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ParseErrorEnum::*;

        f.write_str(
            match self.0 {
                Empty => "empty segment",
                LeadingWhitespace => "segment with leading whitespace",
                TrailingWhitespace => "segment with trailing whitespace",
                ContainsSeparator => "segments contains separator"
            }
        )
    }
}

impl error::Error for ParseSegmentError { }


//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use super::Segment;

    #[test]
    fn test_trailing_separator_fails() {
        assert!(
            Segment::parse(&format!("test{}", Segment::SEPARATOR)).is_err()
        );
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
        assert!(
            Segment::parse(&format!("{}test", Segment::SEPARATOR)).is_err()
        );
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
        assert!(
            Segment::parse(&format!("te{}st", Segment::SEPARATOR)).is_err()
        );
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

