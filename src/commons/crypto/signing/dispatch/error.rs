pub(super) struct ErrorString(String);

impl std::ops::Deref for ErrorString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ErrorString {
    pub fn new<T: std::fmt::Display>(displayable: T) -> Self {
        ErrorString(format!("{}", displayable))
    }
}

impl From<ErrorString> for String {
    fn from(err: ErrorString) -> Self {
        err.0
    }
}

impl<T> From<T> for ErrorString
where
    T: std::fmt::Display,
{
    fn from(err: T) -> Self {
        ErrorString::new(err)
    }
}
