//! Data structures for the API, shared between client and server.
pub mod publishers;
pub mod publication;

//------------ Link ----------------------------------------------------------

/// Defines a link element to include as part of a links array in a Json
/// response.
#[derive(Clone, Debug, Serialize)]
pub struct Link<'a> {
    rel: &'a str,
    link: String
}
