//! Identifiers for components of a storage key.

use std::{error, fmt, mem};
use std::borrow::Cow;
use std::fmt::Write as _;
use std::str::FromStr;
use rpki::ca::idexchange::Handle;
use rpki::crypto::keys::KeyIdentifier;


//------------ Ident ---------------------------------------------------------

/// An identifier for a component of a storage key.
///
/// Idents are strings with a severly limited set of allowed characters.
/// Specifically, only ASCII letters and digits, plus, dash, underscore, and
/// periods are allowed. They can never be empty and they cannot start with
/// a period.
///
/// This type is an unsized type and needs to be used behind some kind of
/// pointer.
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Ident(str);

impl Ident {
    /// Creates a new ident from a byte slice.
    pub const fn from_bytes(bytes: &[u8]) -> Result<&Self, IdentError> {
        if let Err(err) = Self::check_bytes(bytes) {
            return Err(err)
        }

        // Safety: We just checked.
        Ok(unsafe { Self::from_bytes_unchecked(bytes) })
    }

    /// Creates a new ident form a string slice.
    pub const fn from_str(s: &str) -> Result<&Self, IdentError> {
        Self::from_bytes(s.as_bytes())
    }

    /// Creates a ident from the given string slice or panics.
    ///
    /// This function should be used to create segment constants.
    pub const fn make(s: &str) -> &Self {
        match Self::from_str(s) {
            Ok(some) => some,
            Err(_) => panic!("invalid storage identifier")
        }
    }

    /// Creates a new ident from a bytes slice without checking.
    ///
    /// # Safety
    ///
    /// The bytes slice must not be empty and must only contain valid
    /// characters.
    pub const unsafe fn from_bytes_unchecked(s: &[u8]) -> &Self {
        // SAFETY: Self has #repr(transparent)
        unsafe { mem::transmute(s) }
    }

    /// Creates a new boxed ident from a boxed byte slice.
    pub fn from_box(bytes: Box<[u8]>) -> Result<Box<Self>, IdentError> {
        Self::check_bytes(&bytes)?;

        // Safety: We just checked.
        Ok(unsafe { Self::from_box_unchecked(bytes) })
    }

    /// Creates a new boxed ident from a boxed slice without checking.
    ///
    /// # Safety
    ///
    /// The slice must not be empty and must only contain valid characters.
    pub const unsafe fn from_box_unchecked(s: Box<[u8]>) -> Box<Self> {
        // SAFETY: Self has #repr(transparent)
        unsafe { mem::transmute(s) }
    }

    /// Creates a new boxed ident from an owned string.
    pub fn boxed_from_string(s: String) -> Result<Box<Self>, IdentError> {
        Self::check_bytes(s.as_bytes())?;

        // Safety: We just checked.
        Ok(unsafe { Self::boxed_from_string_unchecked(s) })
    }

    /// Creates a new boxed ident from an owned string without checking..
    ///
    /// # Safety
    ///
    /// The string must not be empty and must only contain valid characters.
    pub unsafe fn boxed_from_string_unchecked(s: String) -> Box<Self> {
        unsafe { Self::from_box_unchecked(s.into_boxed_str().into()) }
    }

    /// Checks that `bytes` contains a valid ident.
    const fn check_bytes(mut bytes: &[u8]) -> Result<(), IdentError> {
        let Some(first) = bytes.first() else {
            return Err(IdentError(IdentErrorEnum::Empty))
        };
        if *first == b'.' {
            return Err(IdentError(IdentErrorEnum::LeadingDot))
        }

        while let Some((head, tail)) = bytes.split_first() {
            if !head.is_ascii_alphanumeric()
                && *head != b'+' && *head != b'-' 
                && *head != b'_' && *head != b'.'
            {
                return Err(
                    IdentError(IdentErrorEnum::IllegalCharacter(*head))
                )
            }
            bytes = tail;
        }
        Ok(())
    }

    /// Returns a builder to construct an ident from parts.
    ///
    /// The ident given through `start` will form the first part of the
    /// built ident.
    pub fn builder(start: impl Into<Box<Ident>>) -> IdentBuilder {
        IdentBuilder::new(start)
    }
}

impl Ident {
    // We don’t offer `len` and such. Previously, the scope was a sequence
    // of idents and `len` was used to check if it was a single or multi
    // element scope. So just to be sure to not break something, we leave it
    // out.

    /// Converts the ident to a byte slice.
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Converts the ident to a string slice.
    pub const fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns a boxed ident equal to this ident.
    pub fn to_boxed(&self) -> Box<Self> {
        // Safety: we already have the correct content.
        unsafe { Ident::from_box_unchecked(Box::from(self.as_bytes())) }
    }
}

impl Ident {
    /// Constructs an ident from a number of parts and an optional extension.
    pub fn _from_parts<const N: usize>(
        parts: [&Self; N], extension: Option<&Self>
    ) -> Box<Ident> {
        const { assert!(N > 0) };
        let mut s: String = parts.into_iter().map(Ident::as_str).collect();
        if let Some(extension) = extension {
            s.push('.');
            s.push_str(extension.as_str())
        }

        // Safety: We composed the string out of idents and ensured that
        //         there is at least one (always non-empty) ident before
        //         the period.
        unsafe { Ident::boxed_from_string_unchecked(s) }
    }
}

impl Ident {
    /// Creates an ident from a handle.
    pub fn from_handle<T>(src: &Handle<T>) -> Cow<'_, Self> {
        // The only character allowed in a handle that we can’t have in an
        // ident is a slash but we do have a character that is allowed in
        // idents that isn’t allowed in handles: the plus. So, if we have a
        // slash, we can just do a simple replace if necessary.
        //
        // XXX Krill previously also allowed backslashes. For now we also
        //     replace them with a plus, but we need some sort of migration
        //     strategy to get rid of them.
        let res = if src.as_str().contains(['/', '\\']) {
            // Safety: This assumes that the handle only contains good
            //         characters after replacing.
            Cow::Owned(unsafe {
                Ident::boxed_from_string_unchecked(
                    src.as_str().replace(['/', '\\'], "+")
                )
            })
        }
        else {
            // Safety: This assumes that handle only contains good characters.
            Cow::Borrowed(unsafe {
                Ident::from_bytes_unchecked(src.as_ref())
            })
        };
        debug_assert!(Ident::check_bytes(res.as_bytes()).is_ok());
        res
    }

    /// Creates a handle from an ident if it can.
    ///
    /// If the identifier isn’t a valid handle, returns `None`.
    pub fn to_handle<T>(&self) -> Option<Handle<T>> {
        // XXX Because we currently replace both slashes and backslashes with
        //     plusses, we can’t reliably convert them back. For now we
        //     skip such handles.
        //
        //     We really need to get a, hrm, handle on this situation.
        Handle::from_str(self.as_str()).ok()
    }

    /// Creates an ident from a key identifier.
    pub fn from_key_identifier(src: KeyIdentifier) -> Box<Ident> {
        unsafe {
            Ident::boxed_from_string_unchecked(format!("{src}"))
        }
    }

    /// Creates an ident from the decimal representation of a `u64`.
    pub fn from_u64(src: u64) -> Box<Ident> {
        unsafe {
            Ident::boxed_from_string_unchecked(src.to_string())
        }
    }

    /// Creates an ident from the decimal representation of a `u64`.
    pub fn from_i64(src: i64) -> Box<Ident> {
        unsafe {
            Ident::boxed_from_string_unchecked(src.to_string())
        }
    }

    /// Creates an ident from a string, replacing it if necessary.
    ///
    /// This creates a unique value for any string. A string that is a valid
    /// ident and does not start with an underscore remains what it is. An
    /// empty string becomes a sole underscore. Any other string is replaced
    /// with the hex representation of its octets prefixed with an underscore.
    ///
    pub fn from_str_or_replace(src: &str) -> Cow<'_, Self> {
        if src.is_empty() {
            return Cow::Borrowed(const { Ident::make("_") })
        }
        if !src.starts_with('_') {
            if let Ok(ident) = Self::from_str(src) {
                return Cow::Borrowed(ident)
            }
        }
        let mut res = Vec::with_capacity(src.len() + 1);
        res.push(b'_');
        for ch in src.as_bytes() {
            res.extend_from_slice(&rpki::util::hex::encode_u8(*ch));
        }
        // Safety: only hex digits and underscore
        Cow::Owned(unsafe {
            Ident::from_box_unchecked(
                res.into_boxed_slice()
            )
        })
    }
}


//--- Clone

impl Clone for Box<Ident> {
    fn clone(&self) -> Self {
        // Safety: src is a valid ident.
        unsafe {
            Ident::from_box_unchecked(Box::from(self.as_bytes()))
        }
    }
}


//--- From

impl<'a> From<&'a Ident> for Box<Ident> {
    fn from(src: &'a Ident) -> Self {
        // Safety: src is a valid ident.
        unsafe {
            Ident::from_box_unchecked(Box::from(src.as_bytes()))
        }
    }
}

impl From<Box<Ident>> for Box<str> {
    fn from(src: Box<Ident>) -> Self {
        // Safety: Ident is a transparent wrapper around a str.
        unsafe { mem::transmute(src) }
    }
}


//--- AsRef

impl AsRef<[u8]> for Ident {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<str> for Ident {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}


//--- ToOwned

impl ToOwned for Ident {
    type Owned = Box<Ident>;

    fn to_owned(&self) -> Self::Owned {
        self.to_boxed()
    }
}


//--- Display

impl fmt::Display for Ident {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}


//------------ IdentBuilder --------------------------------------------------

/// Construct an ident from parts.
#[derive(Clone, Debug)]
pub struct IdentBuilder {
    /// The content so far.
    ///
    /// This is guaranteed to contain a valid ident at all times.
    content: String,
}

impl IdentBuilder {
    /// Creates a new builder starting with the given ident.
    ///
    /// Because an ident can never be empty, we always start with something.
    pub fn new(start: impl Into<Box<Ident>>) -> Self {
        IdentBuilder {
            content: Box::<str>::from(start.into()).into()
        }
    }

    /// Adds an ident to the end of the builder.
    pub fn push_ident(mut self, ident: &Ident) -> Self {
        self.content.push_str(ident.as_str());
        self
    }

    /// Adds a single dot to the end of the builder.
    ///
    /// This is a separate function since idents can’t start with a dot.
    pub fn push_dot(mut self) -> Self {
        self.content.push('.');
        self
    }

    /// Adds a handle to the end of the builder.
    pub fn push_handle<T>(mut self, src: &Handle<T>) -> Self {
        // XXX See Ident::from_handle for notes on the whole backslash
        //     malarky.
        let mut parts = src.as_str().split(['/', '\\']);

        // First part goes in directly. Empty handle shouldn’t happen, so
        // we can deal with it in whatever way we see fit.
        //
        // Empty string means the handle started with a slash and we don’t
        // need to treat it specially.
        match parts.next() {
            Some(part) => self.content.push_str(part),
            None => return self,
        }

        // Remaining parts go in with a plus in front. Empty strings mean
        // multiple subsequent slashes, so we can just pretend-append them.
        for part in parts {
            self.content.push('+');
            self.content.push_str(part);
        }

        self
    }

    /// Adds the hex representation of the key identifier to the builder.
    pub fn push_key_identifier(mut self, key: KeyIdentifier) -> Self {
        write!(self.content, "{key}").expect("format to string failed");
        self
    }

    /// Adds the decimal representation of a `u64` to the builder.
    pub fn push_u64(mut self, value: u64) -> Self {
        // This can only fail if we run out of memory, so panicking is okay.
        write!(self.content, "{value}").expect("format to string failed");
        self
    }

    /// Adds the decimal representation of a `i64` to the builder.
    pub fn push_i64(mut self, value: i64) -> Self {
        // This can only fail if we run out of memory, so panicking is okay.
        write!(self.content, "{value}").expect("format to string failed");
        self
    }

    /// Adds a string replacing it if it isn’t a valid ident.
    ///
    /// This creates a unique value for any string. A string that is a valid
    /// ident and does not start with a plus remains what it is. Any
    /// other string is replaced with the hex representation of its octets
    /// prefixed with a plus.
    ///
    /// Nothing will be appended if the string is empty.
    pub fn push_converted_str(mut self, s: &str) -> Self {
        if s.is_empty() {
            return self
        }

        if !s.starts_with("+") && Ident::check_bytes(s.as_bytes()).is_ok() {
            self.content.push_str(s);
            return self
        }
        
        self.content.push('+');
        for ch in s.as_bytes() {
            let hex = rpki::util::hex::encode_u8(*ch);
            self.content.push_str(
                // Safety: the function only returns ASCII hex digits.
                unsafe { std::str::from_utf8_unchecked(&hex) }
            );
        }

        self
    }

    /// Adds a dot followed by an ident and returns the resulting ident.
    pub fn finish_with_extension(self, ident: &Ident) -> Box<Ident> {
        self.push_dot().push_ident(ident).finish()
    }

    /// Finalises building and returns the resulting ident.
    pub fn finish(self) -> Box<Ident> {
        // Safety: We have a valid ident at all times.
        unsafe { Ident::boxed_from_string_unchecked(self.content) }
    }
}


//------------ IdentError ----------------------------------------------------

/// An error happened while parsing an [`Ident`].
#[derive(Clone, Copy, Debug)]
pub struct IdentError(IdentErrorEnum);

#[derive(Clone, Copy, Debug)]
enum IdentErrorEnum {
    Empty,
    LeadingDot,
    IllegalCharacter(u8)
}

impl fmt::Display for IdentError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::IdentErrorEnum::*;

        match self.0 {
            Empty => f.write_str("empty storage identifier"),
            LeadingDot => f.write_str("leading period"),
            IllegalCharacter(n) => {
                match char::from_u32(n.into()) {
                    Some(ch) => {
                        write!(f,
                            "storage identifier with illegal character '{ch}'"
                        )
                    },
                    None => {
                        write!(f,
                            "storage identifier with illegal character \
                             0x{n:02x}'"
                        )
                    }
                }
            }
        }
    }
}

impl error::Error for IdentError { }


