//! Namespaces identifiers.

use std::{borrow, error, fmt, mem, ops, str};


//------------ NamespaceBuf --------------------------------------------------

/// An owned namespace identifier.
///
/// See [`Namespace`] for more details.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct NamespaceBuf(String);


//--- FromStr, From

impl str::FromStr for NamespaceBuf {
    type Err = ParseNamespaceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Namespace::parse(s)?.to_owned())
    }
}

impl From<&Namespace> for NamespaceBuf {
    fn from(value: &Namespace) -> Self {
        value.to_owned()
    }
}


//--- Deref, AsRef, Borrow

impl ops::Deref for NamespaceBuf {
    type Target = Namespace;

    fn deref(&self) -> &Self::Target {
        unsafe { Namespace::from_str_unchecked(&self.0) }
    }
}

impl AsRef<Namespace> for NamespaceBuf {
    fn as_ref(&self) -> &Namespace {
        self
    }
}

impl borrow::Borrow<Namespace> for NamespaceBuf {
    fn borrow(&self) -> &Namespace {
        self
    }
}


//--- Display

impl fmt::Display for NamespaceBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}


//------------ Namespace -----------------------------------------------------

/// A slice with a namespace identifier.
///
/// Namespaces are used by the store to separate different instances that use
/// a shared storage location.
///
/// Namespaces must not contain any characters other than ASCII letters,
/// digits, dash, and underscore. It can at most be 255 characters long.
///
/// For the owned variant of a namespace identifier, see [`NamespaceBuf`].
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct Namespace(str);

impl Namespace {
    /// Parses a namespace from a string slice.
    pub const fn parse(value: &str) -> Result<&Self, ParseNamespaceError> {
        if value.is_empty() {
            return Err(ParseNamespaceError(ParseErrorEnum::Empty))
        }

        if value.len() > 255 {
            return Err(ParseNamespaceError(ParseErrorEnum::TooLong))
        }

        let mut bytes = value.as_bytes();
        while let Some((head, tail)) = bytes.split_first() {
            if !head.is_ascii_alphanumeric()
                && *head != b'-' && *head != b'_'
            {
                return Err(
                    ParseNamespaceError(ParseErrorEnum::IllegalCharacter)
                )
            }
            bytes = tail;
        }

        Ok(unsafe { Namespace::from_str_unchecked(value) })
    }

    /// Creates a namespace from the given slice or panics.
    ///
    /// This function should be used to create segment constants.
    pub const fn make(s: &str) -> &Self {
        match Namespace::parse(s) {
            Ok(some) => some,
            Err(_) => panic!("invalid namespace identifier")
        }
    }

    /// Creates a namespace from a string slice without checking.
    ///
    /// # Safety
    ///
    /// The string slice must not be empty, must only contain valid characters
    /// and must not be longer than 255 characters.
    pub const unsafe fn from_str_unchecked(s: &str) -> &Self {
        // SAFETY: Self has #repr(transparent)
        mem::transmute(s)
    }

    /// Returns a string slice of the namespace.
    pub const fn as_str(&self) -> &str {
        &self.0
    }
}


//--- ToOwned

impl ToOwned for Namespace {
    type Owned = NamespaceBuf;

    fn to_owned(&self) -> Self::Owned {
        NamespaceBuf(self.0.to_owned())
    }
}


//--- Display

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}


//------------ ParseNamespaceError -------------------------------------------

/// An error happened while parsing a string into a [`Namespace`].
#[derive(Clone, Copy, Debug)]
pub struct ParseNamespaceError(ParseErrorEnum);

#[derive(Clone, Copy, Debug)]
enum ParseErrorEnum {
    Empty,
    TooLong,
    IllegalCharacter
}

impl fmt::Display for ParseNamespaceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ParseErrorEnum::*;

        f.write_str(
            match self.0 {
                Empty => "empty namespace",
                TooLong => "namespace longer than 255 characters",
                IllegalCharacter => "namespace contains illegal character",
            }
        )
    }
}

impl error::Error for ParseNamespaceError { }


//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_namespace_fails() {
        assert!(Namespace::parse("").is_err());
    }
}

