use std::str::{from_utf8_unchecked, FromStr};

use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};
use serde::Serialize;

use rpki::x509::Time;

use crate::commons::api::{
    AllCertAuthIssues, CaCommandDetails, CaCommandResult, CaRepoDetails, CertAuthInfo,
    CertAuthIssues, CertAuthList, ChildCaInfo, CommandHistory, CurrentObjects, CurrentRepoState,
    ParentCaContact, PublisherDetails, PublisherList, RepositoryContact, RoaDefinition, ServerInfo,
    StoredEffect,
};
use crate::commons::bgp::{RoaSummary, RoaTable};
use crate::commons::eventsourcing::WithStorableDetails;
use crate::commons::remote::api::ClientInfo;
use crate::commons::remote::rfc8183;
use crate::pubd::RepoStats;

//------------ ApiResponse ---------------------------------------------------

/// This type defines all supported responses for the api
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum ApiResponse {
    Health,
    Info(ServerInfo),

    CertAuthInfo(CertAuthInfo),
    CertAuthHistory(CommandHistory),
    CertAuthAction(CaCommandDetails),
    CertAuths(CertAuthList),
    RouteAuthorizations(Vec<RoaDefinition>),
    RouteAuthorizationsBgpDetails(RoaTable),
    RouteAuthorizationsBgpSummary(RoaSummary),

    ParentCaContact(ParentCaContact),

    ChildInfo(ChildCaInfo),

    PublisherDetails(PublisherDetails),
    PublisherList(PublisherList),
    RepoStats(RepoStats),

    Rfc8181ClientList(Vec<ClientInfo>),
    Rfc8183RepositoryResponse(rfc8183::RepositoryResponse),
    Rfc8183ChildRequest(rfc8183::ChildRequest),
    Rfc8183PublisherRequest(rfc8183::PublisherRequest),

    RepoDetails(CaRepoDetails),
    RepoState(CurrentRepoState),

    CertAuthIssues(CertAuthIssues),
    AllCertAuthIssues(AllCertAuthIssues),

    Empty,               // Typically a successful post just gets an empty 200 response
    GenericBody(String), // For when the server echos Json to a successful post
}

impl ApiResponse {
    pub fn report(&self, fmt: ReportFormat) -> Result<Option<String>, ReportError> {
        if fmt == ReportFormat::None {
            Ok(None)
        } else {
            match self {
                ApiResponse::Health => Ok(None),
                ApiResponse::Info(info) => Ok(Some(info.report(fmt)?)),
                ApiResponse::CertAuths(list) => Ok(Some(list.report(fmt)?)),
                ApiResponse::CertAuthInfo(info) => Ok(Some(info.report(fmt)?)),
                ApiResponse::CertAuthHistory(history) => Ok(Some(history.report(fmt)?)),
                ApiResponse::CertAuthAction(details) => Ok(Some(details.report(fmt)?)),
                ApiResponse::CertAuthIssues(issues) => Ok(Some(issues.report(fmt)?)),
                ApiResponse::AllCertAuthIssues(issues) => Ok(Some(issues.report(fmt)?)),
                ApiResponse::RouteAuthorizations(auths) => Ok(Some(auths.report(fmt)?)),
                ApiResponse::RouteAuthorizationsBgpDetails(table) => Ok(Some(table.report(fmt)?)),
                ApiResponse::RouteAuthorizationsBgpSummary(summary) => {
                    Ok(Some(summary.report(fmt)?))
                }
                ApiResponse::ParentCaContact(contact) => Ok(Some(contact.report(fmt)?)),
                ApiResponse::ChildInfo(info) => Ok(Some(info.report(fmt)?)),
                ApiResponse::PublisherList(list) => Ok(Some(list.report(fmt)?)),
                ApiResponse::PublisherDetails(details) => Ok(Some(details.report(fmt)?)),
                ApiResponse::RepoStats(stats) => Ok(Some(stats.report(fmt)?)),
                ApiResponse::Rfc8181ClientList(list) => Ok(Some(list.report(fmt)?)),
                ApiResponse::Rfc8183ChildRequest(req) => Ok(Some(req.report(fmt)?)),
                ApiResponse::Rfc8183PublisherRequest(req) => Ok(Some(req.report(fmt)?)),
                ApiResponse::Rfc8183RepositoryResponse(res) => Ok(Some(res.report(fmt)?)),
                ApiResponse::RepoDetails(details) => Ok(Some(details.report(fmt)?)),
                ApiResponse::RepoState(state) => Ok(Some(state.report(fmt)?)),
                ApiResponse::GenericBody(body) => Ok(Some(body.clone())),
                ApiResponse::Empty => Ok(None),
            }
        }
    }
}

//------------ ReportFormat --------------------------------------------------

/// This type defines the format to use when representing the api response
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportFormat {
    None,
    Json,
    Text,
}

impl FromStr for ReportFormat {
    type Err = ReportError;

    fn from_str(s: &str) -> Result<Self, ReportError> {
        match s {
            "none" => Ok(ReportFormat::None),
            "json" => Ok(ReportFormat::Json),
            "text" => Ok(ReportFormat::Text),
            _ => Err(ReportError::UnrecognisedFormat(s.to_string())),
        }
    }
}

//------------ ReportError ---------------------------------------------------

/// This type defines possible Errors for KeyStore
#[derive(Debug, Display)]
pub enum ReportError {
    #[display(fmt = "This report format is not supported for this data")]
    UnsupportedFormat,

    #[display(fmt = "This report format is not recognised: {}", _0)]
    UnrecognisedFormat(String),
}

//------------ Report --------------------------------------------------------

/// This trait should be implemented by all api responses, so that the
/// response can be formatted for users.
trait Report: Serialize {
    fn text(&self) -> Result<String, ReportError>;

    fn json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap()
    }

    fn report(&self, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::None => Ok("".to_string()),
            ReportFormat::Json => Ok(self.json()),
            ReportFormat::Text => self.text(),
        }
    }
}

impl Report for CertAuthList {
    fn text(&self) -> Result<String, ReportError> {
        let mut res = String::new();
        for ca in self.cas() {
            res.push_str(&format!("{}\n", ca.handle()));
        }

        Ok(res)
    }
}

impl Report for CertAuthInfo {
    fn text(&self) -> Result<String, ReportError> {
        let mut res = String::new();

        res.push_str(&format!("Name:     {}\n", self.handle()));
        res.push_str("\n");

        if let Some(repo_info) = self.repo_info() {
            let base_uri = repo_info.base_uri();
            let rrdp_uri = repo_info.rpki_notify();
            res.push_str(&format!("Base uri: {}\n", base_uri));
            res.push_str(&format!("RRDP uri: {}\n", rrdp_uri));
        } else {
            res.push_str("No repository configured.")
        }
        res.push_str("\n");

        res.push_str(&format!("ID cert PEM:\n{}\n", self.id_cert().pem()));
        res.push_str(&format!("Hash: {}\n", self.id_cert().hash()));
        res.push_str("\n");

        let resources = self.resources();
        if resources.is_empty() {
            res.push_str("Total resources: <none>\n");
        } else {
            res.push_str("Total resources:\n");
            res.push_str(&format!("    ASNs: {}\n", resources.asn()));
            res.push_str(&format!("    IPv4: {}\n", resources.v4()));
            res.push_str(&format!("    IPv6: {}\n", resources.v6()));
        }
        res.push_str("\n");

        fn print_objects(res: &mut String, objects: &CurrentObjects) {
            for object in objects.names() {
                res.push_str(&format!("  {}\n", object));
            }
        }

        res.push_str("Parents:\n");
        if !self.parents().is_empty() {
            for parent in self.parents().iter() {
                res.push_str(&format!("{}\n", parent));
            }
            res.push_str("\n");
        } else {
            res.push_str("<none>\n")
        }

        for (name, rc) in self.resource_classes() {
            res.push_str(&format!("Resource Class: {}\n", name,));
            res.push_str(&format!("Parent: {}\n", rc.parent_handle()));
            res.push_str(&format!("{}", rc.keys()));

            res.push_str("Current objects:\n");
            print_objects(&mut res, rc.current_objects());
            res.push_str("\n");
        }

        res.push_str("Children:\n");
        if !self.children().is_empty() {
            for child_handle in self.children() {
                res.push_str(&format!("{}\n", child_handle));
            }
        } else {
            res.push_str("<none>\n");
        }

        Ok(res)
    }
}

impl Report for CommandHistory {
    fn text(&self) -> Result<String, ReportError> {
        let mut res = String::new();

        res.push_str("time::command::key::success\n");

        for command in self.commands() {
            let success_string = match &command.effect {
                StoredEffect::Error(msg) => format!("ERROR -> {}", msg),
                StoredEffect::Events(_) => "OK".to_string(),
            };
            res.push_str(&format!(
                "{}::{} ::{}::{}\n",
                command.time().to_rfc3339_opts(SecondsFormat::Secs, true),
                command.summary.msg,
                command.key,
                success_string
            ))
        }

        Ok(res)
    }
}

impl Report for CaCommandDetails {
    fn text(&self) -> Result<String, ReportError> {
        let mut res = String::new();

        let command = self.command();
        res.push_str(&format!(
            "Time:   {}\n",
            command.time().to_rfc3339_opts(SecondsFormat::Secs, true)
        ));
        res.push_str(&format!("Action: {}\n", command.details().summary().msg));

        match self.effect() {
            CaCommandResult::Error(msg) => res.push_str(&format!("Error:  {}\n", msg)),
            CaCommandResult::Events(evts) => {
                res.push_str("Changes:\n");
                for evt in evts {
                    res.push_str(&format!("  {}\n", evt.details().to_string()));
                }
            }
        }

        Ok(res)
    }
}

impl Report for ParentCaContact {
    fn text(&self) -> Result<String, ReportError> {
        let mut res = String::new();
        match self {
            ParentCaContact::Ta(details) => {
                res.push_str(&format!("{}", details.tal()));
            }
            ParentCaContact::Embedded => {
                res.push_str("Embedded parent");
            }
            ParentCaContact::Rfc6492(response) => {
                let bytes = response.encode_vec();
                let xml = unsafe { from_utf8_unchecked(&bytes) };
                res.push_str(xml);
            }
        }
        Ok(res)
    }
}

impl Report for ChildCaInfo {
    fn text(&self) -> Result<String, ReportError> {
        Ok(self.to_string())
    }
}

impl Report for PublisherList {
    fn text(&self) -> Result<String, ReportError> {
        let mut res = String::new();

        res.push_str("Publishers: ");
        let mut first = true;
        for p in self.publishers() {
            if !first {
                res.push_str(", ");
            } else {
                first = false;
            }
            res.push_str(p.handle().as_str());
        }
        Ok(res)
    }
}

impl Report for RepoStats {
    fn text(&self) -> Result<String, ReportError> {
        let mut res = String::new();

        if let Some(update) = self.last_update() {
            res.push_str(&format!("RRDP updated: {}\n", update.to_rfc3339()));
        }
        res.push_str(&format!("RRDP session: {}\n", self.session()));
        res.push_str(&format!("RRDP serial:  {}\n", self.serial()));
        res.push_str("\n");
        res.push_str("Publisher, Objects, Size, Last Updated\n");
        for (publisher, stats) in self.get_publishers() {
            res.push_str(&format!(
                "{}, {}, {}, ",
                publisher,
                stats.objects(),
                stats.size()
            ));
            match stats.last_update() {
                None => res.push_str("never\n"),
                Some(update) => res.push_str(&format!("{}\n", update.to_rfc3339())),
            }
        }

        Ok(res)
    }
}

impl Report for PublisherDetails {
    fn text(&self) -> Result<String, ReportError> {
        let mut res = String::new();

        res.push_str(&format!("handle: {}\n", self.handle()));
        res.push_str(&format!("id: {}", self.id_cert().ski_hex()));
        res.push_str(&format!("base uri: {}\n", self.base_uri().to_string()));

        Ok(res)
    }
}

impl Report for Vec<ClientInfo> {
    fn text(&self) -> Result<String, ReportError> {
        let mut res = String::new();

        res.push_str("Clients: ");
        for client in self.iter() {
            let handle = client.handle();
            let auth = client.auth();
            let ski = auth.cert().ski_hex();

            res.push_str(&format!("   Handle: {}, Cert (ski): {}\n", handle, ski));
        }
        Ok(res)
    }
}

impl Report for rfc8183::RepositoryResponse {
    fn text(&self) -> Result<String, ReportError> {
        let bytes = self.encode_vec();
        let xml = unsafe { from_utf8_unchecked(&bytes) };
        Ok(xml.to_string())
    }
}

impl Report for rfc8183::ChildRequest {
    fn text(&self) -> Result<String, ReportError> {
        let bytes = self.encode_vec();
        let xml = unsafe { from_utf8_unchecked(&bytes) };
        Ok(xml.to_string())
    }
}

impl Report for rfc8183::PublisherRequest {
    fn text(&self) -> Result<String, ReportError> {
        let bytes = self.encode_vec();
        let xml = unsafe { from_utf8_unchecked(&bytes) };
        Ok(xml.to_string())
    }
}

impl Report for Vec<RoaDefinition> {
    fn text(&self) -> Result<String, ReportError> {
        let mut res = String::new();
        for a in self.iter() {
            res.push_str(&format!("{}\n", a));
        }
        Ok(res)
    }
}

impl Report for RoaTable {
    fn text(&self) -> Result<String, ReportError> {
        Ok(self.to_string())
    }
}

impl Report for RoaSummary {
    fn text(&self) -> Result<String, ReportError> {
        Ok(self.to_string())
    }
}

impl Report for CaRepoDetails {
    fn text(&self) -> Result<String, ReportError> {
        let mut res = String::new();

        res.push_str("Repository Details:\n");
        match self.contact() {
            RepositoryContact::Embedded(repo_info) => {
                res.push_str("  type:        embedded\n");
                res.push_str(&format!("  base_uri:    {}\n", repo_info.base_uri()));
                res.push_str(&format!("  rpki_notify: {}\n", repo_info.rpki_notify()));
            }
            RepositoryContact::Rfc8181(response) => {
                res.push_str("  type:        remote\n");
                res.push_str(&format!("  service uri: {}\n", response.service_uri()));
                let repo_info = response.repo_info();
                res.push_str(&format!("  base_uri:    {}\n", repo_info.base_uri()));
                res.push_str(&format!("  rpki_notify: {}\n", repo_info.rpki_notify()));
            }
        }

        res.push_str("\n");

        Ok(res)
    }
}

impl Report for CurrentRepoState {
    fn text(&self) -> Result<String, ReportError> {
        match &self {
            CurrentRepoState::Error(e) => Ok(format!("Error contacting repo! => {}\n", e)),
            CurrentRepoState::List(list) => {
                let mut res = String::new();
                res.push_str("Available and publishing objects:\n");
                let elements = list.elements();
                if elements.is_empty() {
                    res.push_str("  <nothing>\n");
                } else {
                    for el in elements.iter() {
                        res.push_str(&format!("  {} {}\n", el.hash(), el.uri()));
                    }
                }
                Ok(res)
            }
        }
    }
}

impl Report for CertAuthIssues {
    fn text(&self) -> Result<String, ReportError> {
        let mut res = String::new();
        if self.is_empty() {
            res.push_str("no issues found\n")
        } else {
            if let Some(repo_issue) = self.repo_issue() {
                res.push_str(&format!("Repository Issue: {}\n", repo_issue));
            }
            let parent_issues = self.parent_issues();
            if !parent_issues.is_empty() {
                for (parent, issue) in parent_issues.iter() {
                    res.push_str(&format!("Parent '{}' has issue: {}\n", parent, issue));
                }
            }
        }
        Ok(res)
    }
}

impl Report for AllCertAuthIssues {
    fn text(&self) -> Result<String, ReportError> {
        let cas = self.cas();
        let mut res = String::new();
        if cas.is_empty() {
            res.push_str("no issues found\n");
        } else {
            for (ca, issues) in cas.iter() {
                res.push_str(&format!("Found issue for CA '{}':\n", ca));

                if let Some(repo_issue) = issues.repo_issue() {
                    res.push_str(&format!("   Repository Issue: {}\n", repo_issue));
                }
                let parent_issues = issues.parent_issues();
                if !parent_issues.is_empty() {
                    for (parent, issue) in parent_issues.iter() {
                        res.push_str(&format!("   Parent '{}' has issue: {}\n", parent, issue));
                    }
                }
            }
        }
        Ok(res)
    }
}

impl Report for ServerInfo {
    fn text(&self) -> Result<String, ReportError> {
        let dt = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(self.started(), 0), Utc);
        let started = Time::new(dt);
        Ok(format!(
            "Version: {}\nStarted: {}",
            self.version(),
            started.to_rfc3339()
        ))
    }
}
