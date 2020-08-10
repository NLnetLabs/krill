use std::str::FromStr;

use serde::Serialize;

use crate::commons::api::{
    AllCertAuthIssues, CaCommandDetails, CaRepoDetails, CertAuthInfo, CertAuthIssues, CertAuthList, ChildCaInfo,
    CommandHistory, CurrentRepoState, ParentCaContact, ParentStatuses, PublisherDetails, PublisherList, RepoStatus,
    RoaDefinitions, ServerInfo,
};
use crate::commons::bgp::{BgpAnalysisAdvice, BgpAnalysisReport, BgpAnalysisSuggestion};
use crate::commons::remote::api::ClientInfos;
use crate::commons::remote::rfc8183;
use crate::daemon::ca::ResourceTaggedAttestation;
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
    RouteAuthorizations(RoaDefinitions),
    BgpAnalysisAdvice(BgpAnalysisAdvice),
    BgpAnalysisFull(BgpAnalysisReport),
    BgpAnalysisSuggestions(BgpAnalysisSuggestion),

    ParentCaContact(ParentCaContact),
    ParentStatuses(ParentStatuses),

    ChildInfo(ChildCaInfo),

    PublisherDetails(PublisherDetails),
    PublisherList(PublisherList),
    RepoStats(RepoStats),

    Rfc8181ClientList(ClientInfos),
    Rfc8183RepositoryResponse(rfc8183::RepositoryResponse),
    Rfc8183ChildRequest(rfc8183::ChildRequest),
    Rfc8183PublisherRequest(rfc8183::PublisherRequest),

    RepoDetails(CaRepoDetails),
    RepoState(CurrentRepoState),
    RepoStatus(RepoStatus),

    CertAuthIssues(CertAuthIssues),
    AllCertAuthIssues(AllCertAuthIssues),

    Rta(ResourceTaggedAttestation),

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
                ApiResponse::RouteAuthorizations(definitions) => Ok(Some(definitions.report(fmt)?)),
                ApiResponse::BgpAnalysisAdvice(analysis) => Ok(Some(analysis.report(fmt)?)),
                ApiResponse::BgpAnalysisFull(table) => Ok(Some(table.report(fmt)?)),
                ApiResponse::BgpAnalysisSuggestions(suggestions) => Ok(Some(suggestions.report(fmt)?)),
                ApiResponse::ParentCaContact(contact) => Ok(Some(contact.report(fmt)?)),
                ApiResponse::ParentStatuses(statuses) => Ok(Some(statuses.report(fmt)?)),
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
                ApiResponse::RepoStatus(status) => Ok(Some(status.report(fmt)?)),
                ApiResponse::Rta(rta) => Ok(Some(rta.report(fmt)?)),
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
trait Report: Serialize + ToString {
    fn text(&self) -> Result<String, ReportError> {
        Ok(self.to_string())
    }

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

impl Report for CertAuthList {}
impl Report for CertAuthInfo {}

impl Report for ChildCaInfo {}

impl Report for ParentCaContact {}
impl Report for ParentStatuses {}

impl Report for CommandHistory {}
impl Report for CaCommandDetails {}

impl Report for PublisherList {}

impl Report for RepoStats {}

impl Report for PublisherDetails {}

impl Report for ClientInfos {}

impl Report for rfc8183::RepositoryResponse {}
impl Report for rfc8183::ChildRequest {}
impl Report for rfc8183::PublisherRequest {}

impl Report for RoaDefinitions {}

impl Report for BgpAnalysisAdvice {}
impl Report for BgpAnalysisReport {}
impl Report for BgpAnalysisSuggestion {}

impl Report for CaRepoDetails {}
impl Report for CurrentRepoState {}
impl Report for RepoStatus {}

impl Report for CertAuthIssues {}

impl Report for AllCertAuthIssues {}

impl Report for ServerInfo {}

impl Report for ResourceTaggedAttestation {}
