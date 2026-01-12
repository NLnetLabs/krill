//! Prometheus-format metrics.

use std::fmt;
use std::collections::HashMap;
use std::fmt::Write;
use crate::constants::TA_NAME;
use super::super::request::{PathIter, Request};
use super::super::response::HttpResponse;
use super::error::DispatchError;


pub async fn dispatch(
    request: Request<'_>,
    path: PathIter<'_>,
) -> Result<HttpResponse, DispatchError> {
    path.check_exhausted()?;
    request.check_get()?;
    let (request, _) = request.proceed_unchecked();
    let server = request.empty()?;

    let mut target = Target::default();

    target.single(
        Metric::gauge(
            "server_start",
            "Unix timestamp of the last Krill server start",
        ),
        server.server_info().started
    );

    target.single(
        Metric::gauge(
            "version_major",
            "Krill server major version number",
        ),
        env!("CARGO_PKG_VERSION_MAJOR"),
    );
    target.single(
        Metric::gauge(
            "version_minor",
            "Krill server minor version number",
        ),
        env!("CARGO_PKG_VERSION_MINOR"),
    );
    target.single(
        Metric::gauge(
            "version_patch",
            "Krill server patch version number",
        ),
        env!("CARGO_PKG_VERSION_PATCH"),
    );

    #[cfg(feature = "multi-user")]
    target.single(
        Metric::gauge(
            "auth_session_cache_size",
            "total number of cached login session tokens",
        ),
        server.authorizer().login_session_cache_size().await,
    );

    if let Ok(cas_stats) = server.old_krill().cas_stats() {
        target.single(
            Metric::gauge("cas", "number of CAs in Krill"),
            cas_stats.len()
        );


        if !server.config().metrics.metrics_hide_ca_details {
            let mut ca_status_map = HashMap::new();

            for ca in cas_stats.keys() {
                if let Ok(ca_status) = server.old_krill().ca_status(ca) {
                    ca_status_map.insert(ca.clone(), ca_status);
                }
            }

            let metric = Metric::gauge(
                "ca_parent_success",
                "status of last CA to parent connection (1 .. success)",
            );
            target.header(metric);
            for (ca, status) in &ca_status_map {
                if ca.as_str() == TA_NAME {
                    continue
                }

                for (parent, status) in status.parents() {
                    if let Some(exchange) = status.last_exchange.as_ref() {
                        target.multi(metric)
                            .label("ca", ca)
                            .label("parent", parent)
                            .value(i32::from(exchange.result.was_success()))
                    }
                }
            }

            let metric = Metric::gauge(
                "ca_parent_last_success_time",
                "Unix timestamp of last successful CA to parent connection",
            );
            target.header(metric);
            for (ca, status) in &ca_status_map {
                if ca.as_str() == TA_NAME {
                    continue
                }
                for (parent, status) in status.parents() {
                    // Skip parents for which we don’t have had a successful
                    // connection at all. Most likely they were just added
                    // (in which case it will come) - or were never successful
                    // in which case the metric above will say that the status
                    // is 0
                    if let Some(last_success) = status.last_success.as_ref() {
                        target.multi(metric)
                            .label("ca", ca)
                            .label("parent", parent)
                            .value(last_success)
                    }
                }
            }

            let metric = Metric::gauge(
                "ca_ps_success",
                "status of last CA to Publication Server connection \
                 (1 ..success)",
            );
            target.header(metric);
            for (ca, status) in &ca_status_map {
                // Skip the ones for which we have no status yet, i.e
                // it was really only just added
                // and no attempt to connect has yet been made.
                if let Some(exchange) = status.repo().last_exchange.as_ref() {
                    target.multi(metric)
                        .label("ca", ca)
                        .value(i32::from(exchange.result.was_success()))
                }
            }

            let metric = Metric::gauge(
                "ca_ps_last_success_time",
                "unix timestamp of last successful CA to Publication Server \
                 connection",
            );
            target.header(metric);
            for (ca, status) in &ca_status_map {
                // Skip the ones for which we have no status yet, i.e
                // it was really only just added
                // and no attempt to connect has yet been made.
                if let Some(success) = status.repo().last_success.as_ref() {
                    target.multi(metric).label("ca", ca).value(success);
                }
            }

            // Do not show child metrics if none of the CAs has any
            // children.. Many users do not delegate so,
            // showing these metrics would just be confusing.
            let any_children = cas_stats.values().any(|ca| {
                ca.child_count > 0
            });

            if any_children
                && !server.config().metrics.metrics_hide_child_details
            {
                let metric = Metric::gauge(
                    "cas_children",
                    "number of children for CA",
                );
                target.header(metric);
                for (ca, status) in &cas_stats {
                    target.multi(metric)
                        .label("ca", ca)
                        .value(status.child_count)
                }

                let metric = Metric::gauge(
                    "ca_child_success",
                    "status of last child to CA connection",
                );
                target.header(metric);
                for (ca, status) in ca_status_map.iter() {
                    // Skip the ones for which we have no status yet, i.e
                    // it was really only just added
                    // and no attempt to connect has yet been made.
                    for (child, status) in status.children() {
                        if let Some(exchange) = status.last_exchange.as_ref() {
                            target.multi(metric)
                                .label("ca", ca)
                                .label("child", child)
                                .value(
                                    i32::from(exchange.result.was_success())
                                )
                        }
                    }
                }

                let metric = Metric::gauge(
                    "ca_child_state",
                    "child state (0=suspended, 1=active)",
                );
                target.header(metric);
                for (ca, status) in &ca_status_map {
                    for (child, status) in status.children() {
                        target.multi(metric)
                            .label("ca", ca)
                            .label("child", child)
                            .value(i32::from(status.suspended.is_none()))
                   }
                }

                let metric = Metric::gauge(
                    "ca_child_last_connection",
                    "unix timestamp of last child to CA connection",
                );
                target.header(metric);
                for (ca, status) in &ca_status_map {
                    // Skip the ones for which we have no status yet, i.e
                    // it was really only just added
                    // and no attempt to connect has yet been made.
                    for (child, status) in status.children() {
                        if let Some(exchange) = status.last_exchange.as_ref() {
                            target.multi(metric)
                                .label("ca", ca)
                                .label("child", child)
                                .value(exchange.timestamp);
                        }
                    }
                }

                let metric = Metric::gauge(
                    "ca_child_last_success",
                    "unix timestamp last successful child to CA connection",
                );
                target.header(metric);
                for (ca, status) in &ca_status_map {
                    // Skip the ones for which we have no status yet, i.e
                    // it was really only just added
                    // and no attempt to connect has yet been made.
                    for (child, status) in status.children() {
                        if let Some(time) = status.last_success.as_ref() {
                            target.multi(metric)
                                .label("ca", ca)
                                .label("child", child)
                                .value(time);
                        }
                    }
                }

                let metric = Metric::gauge(
                    "ca_child_agent_total",
                    "total children per user agent based on their last \
                     connection",
                );
                target.header(metric);
                for (ca, status) in &ca_status_map {
                    // Skip the ones for which we have no status yet, i.e
                    // it was really only just added
                    // and no attempt to connect has yet been made.

                    let mut user_agent_totals = HashMap::new();
                    for status in status.children().values() {
                        if let Some(exchange) = status.last_exchange.as_ref() {

                            let agent = exchange
                                .user_agent.as_deref()
                                .unwrap_or("<none>");
                            if let Some(item) =
                                user_agent_totals.get_mut(agent)
                            {
                                *item += 1;
                            }
                            else {
                                user_agent_totals.insert(agent.to_string(), 1);
                            }
                        }
                    }

                    for (ua, total) in &user_agent_totals {
                        target.multi(metric)
                            .label("ca", ca)
                            .label("user_agent", ua)
                            .value(total);
                    }
                }
            }

            if !server.config().metrics.metrics_hide_roa_details {
                let metric = Metric::gauge(
                    "cas_bgp_announcements_valid",
                    "number of announcements seen for CA resources \
                     with RPKI state VALID",
                );
                target.header(metric);
                for (ca, stats) in &cas_stats {
                    target.multi(metric)
                        .label("ca", ca)
                        .value(stats.bgp_stats.announcements_valid);
                }

                let metric = Metric::gauge(
                    "cas_bgp_announcements_invalid_asn",
                    "number of announcements seen for CA resources with \
                     RPKI state INVALID (ASN mismatch)",
                );
                target.header(metric);
                for (ca, stats) in &cas_stats {
                    target.multi(metric)
                        .label("ca", ca)
                        .value(stats.bgp_stats.announcements_invalid_asn);
                }

                let metric = Metric::gauge(
                    "cas_bgp_announcements_invalid_length",
                    "number of announcements seen for CA resources with \
                     RPKI state INVALID (prefix exceeds max length)"
                );
                target.header(metric);
                for (ca, stats) in &cas_stats {
                    target.multi(metric)
                        .label("ca", ca)
                        .value(
                            stats.bgp_stats.announcements_invalid_length
                        );
                }

                let metric = Metric::gauge(
                    "cas_bgp_announcements_not_found",
                    "number of announcements seen for CA resources with \
                     RPKI state NOT FOUND (none of the CA's ROAs cover this)"
                );
                target.header(metric);
                for (ca, stats) in &cas_stats {
                    target.multi(metric)
                        .label("ca", ca)
                        .value(stats.bgp_stats.announcements_not_found);
                }

                let metric = Metric::gauge(
                    "cas_bgp_roas_too_permissive",
                    "number of ROAs for this CA which allow excess \
                    announcements (0 may also indicate that no BGP info \
                    is available)"
                );
                target.header(metric);
                for (ca, stats) in &cas_stats {
                    target.multi(metric)
                        .label("ca", ca)
                        .value(stats.bgp_stats.roas_too_permissive);
                }

                let metric = Metric::gauge(
                    "cas_bgp_roas_redundant",
                    "number of ROAs for this CA which are redundant (0 may \
                     also indicate that no BGP info is available)"
                );
                target.header(metric);
                for (ca, stats) in &cas_stats {
                    target.multi(metric)
                        .label("ca", ca)
                        .value(stats.bgp_stats.roas_redundant);
                }

                let metric = Metric::gauge(
                    "cas_bgp_roas_stale",
                    "number of ROAs for this CA for which no announcements \
                    are seen (0 may also indicate that no BGP info is \
                    available)"
                );
                target.header(metric);
                for (ca, stats) in &cas_stats {
                    target.multi(metric)
                        .label("ca", ca)
                        .value(stats.bgp_stats.roas_stale);
                }

                let metric = Metric::gauge(
                    "cas_bgp_roas_total",
                    "total number of ROAs for this CA"
                );
                target.header(metric);
                for (ca, stats) in &cas_stats {
                    target.multi(metric)
                        .label("ca", ca)
                        .value(stats.bgp_stats.roas_total);
                }
            }
        }
    }

    if let Ok(stats) = server.old_krill().repo_stats() {
        target.single(
            Metric::gauge(
                "repo_publisher",
                "number of publishers in repository"
            ),
            stats.publishers.len(),
        );

        if let Some(last_update) = stats.last_update {
            target.single(
                Metric::gauge(
                    "repo_rrdp_last_update",
                    "unix timestamp of last update by any publisher"
                ),
                last_update.timestamp(),
            );
        }

        target.single(
            Metric::counter(
                "repo_rrdp_serial",
                "RRDP serial"
            ),
            stats.serial
        );

        if !server.config().metrics.metrics_hide_publisher_details {
            let metric = Metric::gauge(
                "repo_objects",
                "number of objects in repository for publisher"
            );
            target.header(metric);
            for (publisher, stats) in &stats.publishers {
                target.multi(metric)
                    .label("publisher", publisher)
                    .value(stats.objects)
            }

            let metric = Metric::gauge(
                "repo_size",
                "size of objects in bytes in repository for publisher"
            );
            target.header(metric);
            for (publisher, stats) in &stats.publishers {
                target.multi(metric)
                    .label("publisher", publisher)
                    .value(stats.size);
            }

            let metric = Metric::gauge(
                "repo_last_update",
                "unix timestamp of last update for publisher"
            );
            target.header(metric);
            for (publisher, stats) in &stats.publishers {
                if let Some(last_update) = stats.last_update() {
                    target.multi(metric)
                        .label("publisher", publisher)
                        .value(last_update.timestamp())
                }
            }
        }
    }

    Ok(target.into_response())
}


//============ Metrics Infrastructure ========================================
//
// This is currently copied from Routinator and should perhaps be moved to
// daemonbase.


//------------ Target --------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct Target {
    buf: String,
}

impl Target {
    pub fn into_response(self) -> HttpResponse {
        HttpResponse::prometheus(self.buf.into())
    }

    pub fn single(&mut self, metric: Metric, value: impl fmt::Display) {
        metric.header(self);
        metric.single(self, value);
    }

    pub fn header(&mut self, metric: Metric) {
        metric.header(self)
    }
    
    pub fn multi(&mut self, metric: Metric) -> LabelValue<'_> {
        metric.multi(self)
    }
}


//------------ Metric --------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Metric {
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

    fn multi(self, target: &mut Target) -> LabelValue<'_> {
        LabelValue::new(self, target)
    }
}


//------------ LabelValue ----------------------------------------------------

struct LabelValue<'a> {
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
            &mut self.target.buf, "{name}=\"{value}\""
        ).expect("writing to string");
        self
    }

    pub fn value(self, value: impl fmt::Display) {
        writeln!(
            &mut self.target.buf, "}} {value}"
        ).expect("writing to string");
    }
}


//------------ MetricType ----------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum MetricType {
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

