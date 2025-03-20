//! Reporting client results.

use std::{fmt, io};
use std::io::{stderr, stdout};
use serde::ser::{Serialize, SerializeStruct};
use crate::api::status::Success;

//------------ Report --------------------------------------------------------

pub struct Report {
    /// The content of the report.
    content: Box<dyn ReportContent>,

    /// Does the report stem from an error?
    is_err: bool,
}

impl Report {
    /// Creates a new report that is not an error.
    pub fn new(content: impl ReportContent + 'static) -> Self {
        Self {
            content: Box::new(content),
            is_err: false
        }
    }

    /// Outputs the report.
    ///
    /// Picks either stdout or stderr, depending on whether things went
    /// well or not. Returns the exit code to use.
    pub fn report(self, format: ReportFormat) -> i32 {
        if self.is_err {
            let _ = self.content.write(format, &mut stdout().lock());
            1
        }
        else {
            let _ = self.content.write(format, &mut stderr().lock());
            0
        }
    }

    /// Create a report from a result of an option.
    pub fn from_opt_result<T, E>(src: Result<Option<T>, E>) -> Self
    where
        T: fmt::Display + Serialize + 'static,
        E: fmt::Display + 'static,
    {
        src.map(OptContent).into()
    }
}

impl<T, E> From<Result<T, E>> for Report
where
    T: ReportContent + 'static,
    E: fmt::Display + 'static,
{
    fn from(content: Result<T, E>) -> Self {
        match content {
            Ok(content) => {
                Self {
                    content: Box::new(content),
                    is_err: false,
                }
            }
            Err(content) => {
                Self {
                    content: Box::new(ErrorReport(content)),
                    is_err: true,
                }
            }
        }
    }
}


//------------ ReportContent ------------------------------------------------

pub trait ReportContent {
    fn write(
        &self, format: ReportFormat, target: &mut dyn io::Write
    ) -> Result<(), io::Error>;
}

impl<T: Serialize + fmt::Display> ReportContent for T {
    fn write(
        &self, format: ReportFormat, target: &mut dyn io::Write
    ) -> Result<(), io::Error> {
        match format {
            ReportFormat::None => { Ok(()) }
            ReportFormat::Json => {
                // The &mut here seems to be necessary to avoid a move into
                // the function.
                serde_json::to_writer_pretty(&mut *target, self)?;
                target.write_all(b"\n")?;
                Ok(())
            }
            ReportFormat::Text => {
                writeln!(target, "{}", self)
            }
        }
    }
}


//------------ OptContent ----------------------------------------------------

struct OptContent<T>(Option<T>);

impl<T: fmt::Display> fmt::Display for OptContent<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            Some(content) => content.fmt(f),
            None => Success.fmt(f)
        }
    }
}

impl<T: Serialize> Serialize for OptContent<T> {
    fn serialize<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Some(content) => content.serialize(serializer),
            None => Success.serialize(serializer),
        }
    }
}


//------------ ErrorReport ---------------------------------------------------

struct ErrorReport<T>(T);

impl<T: fmt::Display> fmt::Display for ErrorReport<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: fmt::Display> Serialize for ErrorReport<T> {
    fn serialize<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        let mut serializer = serializer.serialize_struct(
            "HttpClientError", 1
        )?;
        serializer.serialize_field("error", &format_args!("{}", self.0))?;
        serializer.end()
    }
}



//------------ ReportFormat --------------------------------------------------

/// This type defines the format to use when representing the api response
#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum ReportFormat {
    None,
    Json,
    Text,
}

