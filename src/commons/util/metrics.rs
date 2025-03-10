//! Building metrics.
//!
//! This is currently copied from Routinator and should perhaps be moved to
//! daemonbase.

use std::fmt;
use std::fmt::Write;


//------------ Target --------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct Target {
    buf: String,
}

impl Target {
    pub fn into_vec(self) -> Vec<u8> {
        self.buf.into()
    }

    pub fn single(&mut self, metric: Metric, value: impl fmt::Display) {
        metric.header(self);
        metric.single(self, value);
    }

    pub fn header(&mut self, metric: Metric) {
        metric.header(self)
    }
    
    pub fn multi(&mut self, metric: Metric) -> LabelValue {
        metric.multi(self)
    }
}


//------------ Metric --------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Metric {
    prefix: &'static str,
    name: &'static str,
    help: (&'static str, &'static str),
    mtype: MetricType,
}

impl Metric {
    pub fn new(
        name: &'static str, help: &'static str, mtype: MetricType
    ) -> Self {
        Metric {
            prefix: "",
            name,
            help: (help, ""),
            mtype
        }
    }

    pub fn counter(name: &'static str, help: &'static str) -> Self {
        Self::new(name, help, MetricType::Counter)
    }

    pub fn gauge(name: &'static str, help: &'static str) -> Self {
        Self::new(name, help, MetricType::Gauge)
    }

    fn header(self, target: &mut Target) {
        writeln!(&mut target.buf,
            "# HELP krill{}_{} {}{}\n\
             # TYPE krill{}_{} {}",
            self.prefix, self.name, self.help.0, self.help.1,
            self.prefix, self.name, self.mtype,
        ).expect("writing to string");
    }

    fn single(self, target: &mut Target, value: impl fmt::Display) {
        writeln!(&mut target.buf,
            "krill{}_{} {}",
            self.prefix, self.name, value
        ).expect("writing to string");
    }

    fn multi(self, target: &mut Target) -> LabelValue {
        LabelValue::new(self, target)
    }
}


//------------ LabelValue ----------------------------------------------------

pub struct LabelValue<'a> {
    target: &'a mut Target,
    first: bool,
}

impl<'a> LabelValue<'a> {
    fn new(metric: Metric, target: &'a mut Target) -> Self {
        write!(
            &mut target.buf, "krill{}_{}{{", metric.prefix, metric.name
        ).expect("writing to string");
        LabelValue { target, first: true }
    }

    pub fn label(mut self, name: &str, value: impl fmt::Display) -> Self {
        if self.first {
            self.first = false;
        }
        else {
            self.target.buf.push_str(", ");
        }
        write!(
            &mut self.target.buf, "{}=\"{}\"", name, value
        ).expect("writing to string");
        self
    }

    pub fn value(self, value: impl fmt::Display) {
        writeln!(
            &mut self.target.buf, "}} {}", value
        ).expect("writing to string");
    }
}


//------------ MetricType ----------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum MetricType {
    Counter,
    Gauge,
    /* Not currently used:
    Histogram,
    Summary,
    */
}

impl fmt::Display for MetricType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(
            match *self {
                MetricType::Counter => "counter",
                MetricType::Gauge => "gauge",
                /*
                MetricType::Histogram => "histogram",
                MetricType::Summary => "summary",
                */
            }
        )
    }
}

