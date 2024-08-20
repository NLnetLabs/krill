//! Types for argument values.

use std::{error, fmt, io};
use std::fs::File;
use std::io::BufReader;
use std::marker::PhantomData;
use std::str::FromStr;


//------------ JsonFile ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct JsonFile<T, Msg> {
    pub content: T,
    marker: PhantomData<Msg>,
}

impl<T, Msg> FromStr for JsonFile<T, Msg>
where
    T: serde::de::DeserializeOwned,
    Msg: Default + fmt::Display
{
    type Err = JsonFileError<Msg>;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        serde_json::from_reader::<_, T>(
            BufReader::new(
                File::open(path).map_err(|err| {
                    JsonFileError::Io(path.into(), Default::default(), err)
                })?
            )
        ).map(|content| {
            Self { content, marker: PhantomData }
        }).map_err(|err| {
            JsonFileError::Parse(path.into(), Default::default(), err)
        })
    }
}


//============ ErrorTypes ====================================================

//------------ JsonFileError -------------------------------------------------

#[derive(Debug)]
pub enum JsonFileError<Msg> {
    Io(String, Msg, io::Error),
    Parse(String, Msg, serde_json::Error),
}

impl<Msg: fmt::Display> fmt::Display for JsonFileError<Msg> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(path, msg, err) => {
                write!(
                    f, "Failed to read {} file '{}': {}'",
                    msg, path, err
                )
            }
            Self::Parse(path, msg, err) => {
                write!(
                    f, "Failed to parse {} file '{}': {}'",
                    msg, path, err
                )
            }
        }
    }
}

impl<Msg: fmt::Display + fmt::Debug> error::Error for JsonFileError<Msg> { }

