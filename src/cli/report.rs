use std::fmt;
use std::str::FromStr;

use serde::Serialize;

use rpki::ca::idexchange;

use crate::{
    commons::{
        api::{
            AllCertAuthIssues, AspaDefinitionList, BgpSecCsrInfoList, CaCommandDetails, CaRepoDetails, CertAuthInfo,
            CertAuthIssues, CertAuthList, ChildCaInfo, ChildrenConnectionStats, CommandHistory, ConfiguredRoas,
            IdCertInfo, ParentCaContact, ParentStatuses, PublisherDetails, PublisherList, RepoStatus,
            RepositoryContact, RtaList, RtaPrepResponse, ServerInfo,
        },
        bgp::{BgpAnalysisAdvice, BgpAnalysisReport, BgpAnalysisSuggestion},
    },
    daemon::{
        ca::ResourceTaggedAttestation,
        ta::{TrustAnchorSignerInfo, TrustAnchorSignerRequest, TrustAnchorSignerResponse},
    },
    pubd::RepoStats,
};

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

    // ROA related
    RouteAuthorizations(ConfiguredRoas),
    BgpAnalysisAdvice(BgpAnalysisAdvice),
    BgpAnalysisFull(BgpAnalysisReport),
    BgpAnalysisSuggestions(BgpAnalysisSuggestion),

    // ASPA related
    AspaDefinitions(AspaDefinitionList),

    // BGPSec related
    BgpSecDefinitions(BgpSecCsrInfoList),

    ParentCaContact(ParentCaContact),
    ParentStatuses(ParentStatuses),

    ChildInfo(ChildCaInfo),
    ChildrenStats(ChildrenConnectionStats),

    PublisherDetails(PublisherDetails),
    PublisherList(PublisherList),
    RepoStats(RepoStats),

    Rfc8183ParentResponse(idexchange::ParentResponse),
    Rfc8183RepositoryResponse(idexchange::RepositoryResponse),
    Rfc8183ChildRequest(idexchange::ChildRequest),
    Rfc8183PublisherRequest(idexchange::PublisherRequest),

    RepoDetails(CaRepoDetails),
    RepoStatus(RepoStatus),

    CertAuthIssues(CertAuthIssues),
    AllCertAuthIssues(AllCertAuthIssues),

    RtaList(RtaList),
    RtaMultiPrep(RtaPrepResponse),
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
                ApiResponse::AspaDefinitions(definitions) => Ok(Some(definitions.report(fmt)?)),
                ApiResponse::BgpSecDefinitions(definitions) => Ok(Some(definitions.report(fmt)?)),
                ApiResponse::ParentCaContact(contact) => Ok(Some(contact.report(fmt)?)),
                ApiResponse::ParentStatuses(statuses) => Ok(Some(statuses.report(fmt)?)),
                ApiResponse::ChildInfo(info) => Ok(Some(info.report(fmt)?)),
                ApiResponse::ChildrenStats(stats) => Ok(Some(stats.report(fmt)?)),
                ApiResponse::PublisherList(list) => Ok(Some(list.report(fmt)?)),
                ApiResponse::PublisherDetails(details) => Ok(Some(details.report(fmt)?)),
                ApiResponse::RepoStats(stats) => Ok(Some(stats.report(fmt)?)),
                ApiResponse::Rfc8183ParentResponse(res) => Ok(Some(res.report(fmt)?)),
                ApiResponse::Rfc8183ChildRequest(req) => Ok(Some(req.report(fmt)?)),
                ApiResponse::Rfc8183PublisherRequest(req) => Ok(Some(req.report(fmt)?)),
                ApiResponse::Rfc8183RepositoryResponse(res) => Ok(Some(res.report(fmt)?)),
                ApiResponse::RepoDetails(details) => Ok(Some(details.report(fmt)?)),
                ApiResponse::RepoStatus(status) => Ok(Some(status.report(fmt)?)),
                ApiResponse::Rta(rta) => Ok(Some(rta.report(fmt)?)),
                ApiResponse::RtaList(list) => Ok(Some(list.report(fmt)?)),
                ApiResponse::RtaMultiPrep(res) => Ok(Some(res.report(fmt)?)),
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
            _ => Err(ReportError::UnrecognizedFormat(s.to_string())),
        }
    }
}

//------------ ReportError ---------------------------------------------------

/// This type defines possible Errors for KeyStore
#[derive(Debug)]
pub enum ReportError {
    UnsupportedFormat,
    UnrecognizedFormat(String),
}

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReportError::UnsupportedFormat => write!(f, "This report format is not supported for this data"),
            ReportError::UnrecognizedFormat(s) => write!(f, "This report format is not recognized: {}", s),
        }
    }
}

//------------ Report --------------------------------------------------------

/// This trait should be implemented by all api responses, so that the
/// response can be formatted for users.
pub trait Report: Serialize + ToString {
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
impl Report for IdCertInfo {}
impl Report for RepositoryContact {}

impl Report for ChildCaInfo {}

impl Report for ParentCaContact {}
impl Report for ParentStatuses {}

impl Report for CommandHistory {}
impl Report for CaCommandDetails {}

impl Report for PublisherList {}

impl Report for RepoStats {}
impl Report for ChildrenConnectionStats {}

impl Report for PublisherDetails {}

impl Report for idexchange::RepositoryResponse {
    fn text(&self) -> Result<String, ReportError> {
        Ok(self.to_xml_string())
    }
}

impl Report for idexchange::ParentResponse {
    fn text(&self) -> Result<String, ReportError> {
        Ok(self.to_xml_string())
    }
}

impl Report for idexchange::ChildRequest {
    fn text(&self) -> Result<String, ReportError> {
        Ok(self.to_xml_string())
    }
}

impl Report for idexchange::PublisherRequest {
    fn text(&self) -> Result<String, ReportError> {
        Ok(self.to_xml_string())
    }
}

impl Report for ConfiguredRoas {}

impl Report for BgpAnalysisAdvice {}
impl Report for BgpAnalysisReport {}
impl Report for BgpAnalysisSuggestion {}

impl Report for AspaDefinitionList {}

impl Report for BgpSecCsrInfoList {}

impl Report for CaRepoDetails {}
impl Report for RepoStatus {}

impl Report for CertAuthIssues {}

impl Report for AllCertAuthIssues {}

impl Report for ServerInfo {}

impl Report for ResourceTaggedAttestation {}
impl Report for RtaList {}
impl Report for RtaPrepResponse {}

impl Report for TrustAnchorSignerInfo {}
impl Report for TrustAnchorSignerRequest {}
impl Report for TrustAnchorSignerResponse {}
