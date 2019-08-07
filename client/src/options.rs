use clap::{App, Arg, SubCommand};
use rpki::uri;
use std::io;
use std::path::PathBuf;
use std::str::FromStr;

use krill_commons::api::admin::{
    AddChildRequest, AddParentRequest, CertAuthInit, CertAuthPubMode, ChildAuthRequest, Handle,
    ParentCaContact, Token, UpdateChildRequest,
};
use krill_commons::api::ca::{ResSetErr, ResourceSet};
use krill_commons::remote::rfc8183;
use krill_commons::util::file;

use crate::report::{ReportError, ReportFormat};

/// This type holds all the necessary data to connect to a Krill daemon, and
/// authenticate, and perform a specific action. Note that this is extracted
/// from the bin/krillc.rs, so that we can use this in integration testing
/// more easily.
pub struct Options {
    pub server: uri::Https,
    pub token: Token,
    pub format: ReportFormat,
    pub command: Command,
}

impl Options {
    pub fn format(&self) -> ReportFormat {
        self.format
    }

    /// Creates a new Options explicitly (useful for testing)
    pub fn new(server: uri::Https, token: &str, format: ReportFormat, command: Command) -> Self {
        Options {
            server,
            token: Token::from(token),
            format,
            command,
        }
    }

    /// Creates a new Options from command line args (useful for cli)
    #[allow(clippy::cognitive_complexity)] // there are just many options
    pub fn from_args() -> Result<Options, Error> {
        let matches = App::new("Krill admin client")
            .version("0.2.0")
            .arg(Arg::with_name("server")
                .short("s")
                .long("server")
                .value_name("URI")
                .help("Specify the full URI to the krill server.")
                .required(true))
            .arg(Arg::with_name("token")
                .short("t")
                .long("token")
                .value_name("token-string")
                .help("Specify the value of an admin token.")
                .required(true))
            .arg(Arg::with_name("format")
                .short("f")
                .long("format")
                .value_name("type")
                .help(
                    "Specify the report format (none|json|text|xml). If \
                    left unspecified the format will match the \
                    corresponding server api response type.")
                .required(false)
            )
            .subcommand(SubCommand::with_name("health")
                .about("Perform a health check. Exits with exit code 0 if \
                all is well, exit code 1 in case of any issues")
            )

            .subcommand(SubCommand::with_name("trustanchor")
                .about("Manage embedded Trust Anchor (used for testing)")
                .subcommand(SubCommand::with_name("init")
                    .about("Initialise embedded TA.")
                )
                .subcommand(SubCommand::with_name("show")
                    .about("Show embedded TA details.")
                )
                .subcommand(SubCommand::with_name("publish")
                    .about("Force publication for embedded TA now.")
                )
                .subcommand(SubCommand::with_name("children")
                    .about("Manage children of the embbeded TA")
                    .subcommand(SubCommand::with_name("add")
                        .about("Add a child to the embedded CA")

                        .arg(Arg::with_name("asn")
                            .short("a")
                            .long("asn")
                            .value_name("AS resources")
                            .help("The delegated AS resources: e.g. AS1, AS3-4")
                            .required(false)
                        )
                        .arg(Arg::with_name("ipv4")
                            .short("4")
                            .long("ipv4")
                            .value_name("IPv4 resources")
                            .help("The delegated IPv4 resources: e.g. 192.168.0.0/16")
                            .required(false)
                        )
                        .arg(Arg::with_name("ipv6")
                            .short("6")
                            .long("ipv6")
                            .value_name("IPv6 resources")
                            .help("The delegated IPv6 resources: e.g. 2001:db8::/32")
                            .required(false)
                        )

                        .subcommand(SubCommand::with_name("krill")
                            .about("Add a krill child, using token auth")
                            .arg(Arg::with_name("handle")
                                .short("h")
                                .long("handle")
                                .value_name("child-handle")
                                .help("The handle (name) for the child CA")
                                .required(true)
                            )
                            .arg(Arg::with_name("token")
                                .short("t")
                                .long("token")
                                .value_name("token-string")
                                .help("The auth token between the child and TA")
                                .required(true)
                            )
                        )

                        .subcommand(SubCommand::with_name("rfc6492")
                            .about("Add an RFC 6492 child")
                            .arg(Arg::with_name("handle")
                                .short("h")
                                .long("handle")
                                .value_name("child-handle")
                                .help("Override the handle in the XML")
                                .required(false)
                            )
                            .arg(Arg::with_name("token")
                                .short("t")
                                .long("token")
                                .value_name("token-string")
                                .help("The auth token, defaults to a random token")
                                .required(false)
                            )
                            .arg(Arg::with_name("xml")
                                .short("x")
                                .long("xml")
                                .value_name("FILE")
                                .help("RFC 8183 Child Request XML")
                                .required(true)
                            )
                        )
                    )
                    .subcommand(SubCommand::with_name("update")
                        .about("Update details for a child")
                        .arg(Arg::with_name("handle")
                            .short("h")
                            .long("handle")
                            .value_name("child-handle")
                            .help("Override the handle in the XML")
                            .required(false)
                        )
                        .arg(Arg::with_name("token")
                            .short("t")
                            .long("token")
                            .value_name("token-string")
                            .help("Update the authentication token for the child")
                            .required(false)
                        )
                        .arg(Arg::with_name("xml")
                            .short("x")
                            .long("xml")
                            .value_name("FILE")
                            .help("Update child certificate from RFC 8183 Child Request XML")
                            .required(false)
                        )
                        .arg(Arg::with_name("asn")
                            .short("a")
                            .long("asn")
                            .value_name("AS resources")
                            .help("Update the delegated AS resources: e.g. AS1, AS3-4")
                            .required(false)
                        )
                        .arg(Arg::with_name("ipv4")
                            .short("4")
                            .long("ipv4")
                            .value_name("IPv4 resources")
                            .help("Update the delegated IPv4 resources: e.g. 192.168.0.0/16")
                            .required(false)
                        )
                        .arg(Arg::with_name("ipv6")
                            .short("6")
                            .long("ipv6")
                            .value_name("IPv6 resources")
                            .help("Update the delegated IPv6 resources: e.g. 2001:db8::/32")
                            .required(false)
                        )


                    )
                )
            )

            .subcommand(SubCommand::with_name("cas")
                .about("Manage CAs")
                .subcommand(SubCommand::with_name("list")
                    .about("Show current CAs")
                )
                .subcommand(SubCommand::with_name("show")
                    .about("Show CA details)")
                    .arg(Arg::with_name("handle")
                        .short("h")
                        .long("handle")
                        .value_name("handle")
                        .help("The handle (name) for the CA")
                        .required(true)
                    )
                )
                .subcommand(SubCommand::with_name("rfc8183_child_request")
                    .about("The RFC8183 Child Request for a CA")
                    .arg(Arg::with_name("handle")
                        .short("h")
                        .long("handle")
                        .value_name("handle")
                        .help("The handle (name) for the CA")
                        .required(true)
                    )
                )

                .subcommand(SubCommand::with_name("keyroll")
                    .about("Perform a manual key roll for a CA")
                    .arg(Arg::with_name("handle")
                        .short("h")
                        .long("handle")
                        .value_name("handle")
                        .help("The handle (name) for the CA")
                        .required(true)
                    )
                    .subcommand(SubCommand::with_name("init")
                        .about("Initialise a key roll for all active keys")
                    )
                )

                .subcommand(SubCommand::with_name("add")
                    .about("Add a new CA)")
                    .arg(Arg::with_name("handle")
                        .short("h")
                        .long("handle")
                        .value_name("child-handle")
                        .help("The handle (name) for the child CA")
                        .required(true)
                    )
                    .arg(Arg::with_name("token")
                        .short("ct")
                        .long("token")
                        .value_name("token-string")
                        .help("The auth token to control the CA")
                        .required(true)
                    )
                )
                .subcommand(SubCommand::with_name("update")
                    .about("Update an existing CA")
                    .arg(Arg::with_name("handle")
                        .short("h")
                        .long("handle")
                        .value_name("ca handle")
                        .help("The handle (name) for the CA")
                        .required(true)
                    )
                    .subcommand(SubCommand::with_name("add-parent")
                        .about("Add a parent to a CA (only embedded for now)")

                        .arg(Arg::with_name("parent")
                            .short("p")
                            .long("parent")
                            .value_name("parent ca handle")
                            .help("The local handle (name) for the parent CA")
                            .required(true)
                        )

                        .subcommand(SubCommand::with_name("embedded")
                            .about("Add an embedded parent")

                            .arg(Arg::with_name("token")
                                .short("t")
                                .long("token")
                                .value_name("token-string")
                                .help("The auth token the parent knows for the CA")
                                .required(true)
                            )
                        )

                        .subcommand(SubCommand::with_name("rfc6492")
                            .about("Add an RFC6492 parent")
                            .arg(Arg::with_name("xml")
                                .short("x")
                                .long("xml")
                                .value_name("response.xml")
                                .help("The RFC8183 response xml file")
                                .required(true)
                            )
                        )


                    )

                )
            )

            .subcommand(SubCommand::with_name("publishers")
                .about("Manage publishers")
                .subcommand(SubCommand::with_name("list")
                    .about("List all current publishers")
                )
                .subcommand(SubCommand::with_name("add")
                    .about("Add an API using publisher.")
                    .arg(Arg::with_name("token")
                        .short("t")
                        .long("token")
                        .value_name("text")
                        .help("Specify a token string.")
                        .required(true)
                    )
                    .arg(Arg::with_name("uri")
                        .short("u")
                        .long("uri")
                        .value_name("rsync uri")
                        .help("Rsync base uri for publisher. Must be covered by server, and not overlap with existing publishers.")
                        .required(true)
                    )
                    .arg(Arg::with_name("handle")
                        .short("h")
                        .long("handle")
                        .value_name("name")
                        .help("A unique name for this publisher. Must be a-Z0-9 without spaces.")
                        .required(true)
                    )
                )
                .subcommand(SubCommand::with_name("details")
                    .about("Show details for a publisher.")
                    .arg(Arg::with_name("handle")
                        .short("h")
                        .long("handle")
                        .value_name("publisher handle")
                        .help("The publisher handle from RFC8181")
                        .required(true)
                    )
                )
                .subcommand(SubCommand::with_name("deactivate")
                    .about("Removes a known publisher")
                    .arg(Arg::with_name("handle")
                        .short("h")
                        .long("handle")
                        .value_name("publisher handle")
                        .help("The publisher handle from RFC8181")
                        .required(true)
                    )
                )
            )
            .subcommand(SubCommand::with_name("rfc8181")
                .about("Manage RFC8181 clients")
                .subcommand(SubCommand::with_name("list")
                    .about("List all current clients with details")
                )
                .subcommand(SubCommand::with_name("add")
                    .about("Add RFC8181 client (assumes handle is in the XML)")
                    .arg(Arg::with_name("xml")
                        .short("x")
                        .long("xml")
                        .value_name("FILE")
                        .help("Specify a file containing an RFC8183 \
                        publisher request. (See: https://tools.ietf.org/html/rfc8183#section-5.2.3)")
                        .required(true)
                    )
                )
                .subcommand(SubCommand::with_name("repo-res")
                    .about("Show the RFC8181 repository response xml")
                    .arg(Arg::with_name("handle")
                        .short("h")
                        .long("handle")
                        .value_name("publisher handle")
                        .help("The publisher handle from RFC8181")
                        .required(true)
                    )
                )
            )
            .get_matches();

        let mut command = Command::NotSet;

        if let Some(_m) = matches.subcommand_matches("health") {
            command = Command::Health;
        }

        if let Some(m) = matches.subcommand_matches("trustanchor") {
            if let Some(_m) = m.subcommand_matches("show") {
                command = Command::TrustAnchor(TrustAnchorCommand::Show)
            }
            if let Some(_m) = m.subcommand_matches("init") {
                command = Command::TrustAnchor(TrustAnchorCommand::Init)
            }
            if let Some(_m) = m.subcommand_matches("publish") {
                command = Command::TrustAnchor(TrustAnchorCommand::Publish)
            }
            if let Some(m) = m.subcommand_matches("children") {
                if let Some(m) = m.subcommand_matches("add") {
                    let asn = m.value_of("asn").unwrap_or("");
                    let ipv4 = m.value_of("ipv4").unwrap_or("");
                    let ipv6 = m.value_of("ipv6").unwrap_or("");

                    if let Some(m) = m.subcommand_matches("embedded") {
                        let handle = Handle::from(m.value_of("handle").unwrap());
                        let token = Token::from(m.value_of("token").unwrap());
                        let res = ResourceSet::from_strs(asn, ipv4, ipv6).unwrap();

                        let auth = ChildAuthRequest::Embedded(token);

                        let req = AddChildRequest::new(handle, res, auth);
                        command = Command::TrustAnchor(TrustAnchorCommand::AddChild(req))
                    }

                    if let Some(m) = m.subcommand_matches("rfc6492") {
                        let xml_path = m.value_of("xml").unwrap();
                        let xml = PathBuf::from(xml_path);
                        let bytes = file::read(&xml)?;
                        let cr = rfc8183::ChildRequest::validate(bytes.as_ref())?;

                        let handle = {
                            if let Some(handle) = m.value_of("handle") {
                                Handle::from(handle)
                            } else {
                                cr.child_handle().clone()
                            }
                        };

                        let res = ResourceSet::from_strs(asn, ipv4, ipv6)?;

                        let auth = ChildAuthRequest::Rfc8183(cr);

                        let req = AddChildRequest::new(handle, res, auth);
                        command = Command::TrustAnchor(TrustAnchorCommand::AddChild(req))
                    }
                }

                if let Some(m) = m.subcommand_matches("update") {
                    let handle = Handle::from(m.value_of("handle").unwrap());
                    let token = m.value_of("token").map(Token::from);
                    let cert = match m.value_of("xml") {
                        Some(xml_path) => {
                            let xml = PathBuf::from(xml_path);
                            let bytes = file::read(&xml)?;
                            let cr = rfc8183::ChildRequest::validate(bytes.as_ref())?;
                            let (_, _, cert) = cr.unwrap();
                            Some(cert)
                        }
                        None => None,
                    };

                    let asn = m.value_of("asn").unwrap_or("");
                    let ipv4 = m.value_of("ipv4").unwrap_or("");
                    let ipv6 = m.value_of("ipv6").unwrap_or("");
                    let resources = ResourceSet::from_strs(asn, ipv4, ipv6)?;

                    let resources = if resources.is_empty() {
                        None
                    } else {
                        Some(resources)
                    };

                    let req = UpdateChildRequest::new(token, cert, resources);

                    command = Command::TrustAnchor(TrustAnchorCommand::UpdateChild(handle, req))
                }
            }
        }

        if let Some(m) = matches.subcommand_matches("cas") {
            if let Some(m) = m.subcommand_matches("add") {
                let handle = Handle::from(m.value_of("handle").unwrap());
                let token = Token::from(m.value_of("token").unwrap());
                let pub_mode = CertAuthPubMode::Embedded;

                let init = CertAuthInit::new(handle, token, pub_mode);
                command = Command::CertAuth(CaCommand::Init(init));
            }
            if let Some(m) = m.subcommand_matches("rfc8183_child_request") {
                let handle = Handle::from(m.value_of("handle").unwrap());
                command = Command::CertAuth(CaCommand::ChildRequest(handle));
            }
            if let Some(_m) = m.subcommand_matches("list") {
                command = Command::CertAuth(CaCommand::List);
            }
            if let Some(m) = m.subcommand_matches("keyroll") {
                let handle = Handle::from(m.value_of("handle").unwrap());
                if let Some(_m) = m.subcommand_matches("init") {
                    command = Command::CertAuth(CaCommand::KeyRollInit(handle));
                }
            }

            if let Some(m) = m.subcommand_matches("show") {
                let handle = Handle::from(m.value_of("handle").unwrap());
                command = Command::CertAuth(CaCommand::Show(handle));
            }
            if let Some(m) = m.subcommand_matches("update") {
                let handle = Handle::from(m.value_of("handle").unwrap());

                if let Some(m) = m.subcommand_matches("add-parent") {
                    let parent = Handle::from(m.value_of("parent").unwrap());

                    if let Some(m) = m.subcommand_matches("embedded") {
                        let token = Token::from(m.value_of("token").unwrap());

                        let contact = ParentCaContact::Embedded(parent.clone(), token);

                        let req = AddParentRequest::new(parent, contact);

                        command = Command::CertAuth(CaCommand::AddParent(handle, req))
                    } else if let Some(m) = m.subcommand_matches("rfc6492") {
                        let xml_path = m.value_of("xml").unwrap();
                        let xml = PathBuf::from(xml_path);
                        let bytes = file::read(&xml)?;
                        let pr = rfc8183::ParentResponse::validate(bytes.as_ref())?;

                        let contact = ParentCaContact::Rfc6492(pr);
                        let req = AddParentRequest::new(parent, contact);

                        command = Command::CertAuth(CaCommand::AddParent(handle, req));
                    }
                }
            }
        }

        if let Some(m) = matches.subcommand_matches("publishers") {
            if let Some(_m) = m.subcommand_matches("list") {
                command = Command::Publishers(PublishersCommand::List)
            }
            if let Some(m) = m.subcommand_matches("add") {
                let handle = Handle::from(m.value_of("handle").unwrap());
                let base_uri = uri::Rsync::from_str(m.value_of("uri").unwrap())?;
                let token = Token::from(m.value_of("token").unwrap());

                let add = AddPublisher {
                    handle,
                    base_uri,
                    token,
                };
                command = Command::Publishers(PublishersCommand::Add(add));
            }
            if let Some(m) = m.subcommand_matches("details") {
                let handle = m.value_of("handle").unwrap();
                let details = PublishersCommand::Details(handle.to_string());
                command = Command::Publishers(details);
            }
            if let Some(m) = m.subcommand_matches("deactivate") {
                let handle = m.value_of("handle").unwrap().to_string();
                command = Command::Publishers(PublishersCommand::Deactivate(handle))
            }
        }

        if let Some(m) = matches.subcommand_matches("rfc8181") {
            if let Some(_m) = m.subcommand_matches("list") {
                command = Command::Rfc8181(Rfc8181Command::List)
            }
            if let Some(m) = m.subcommand_matches("add") {
                let xml_path = m.value_of("xml").unwrap();
                let xml = PathBuf::from(xml_path);

                command = Command::Rfc8181(Rfc8181Command::Add(AddRfc8181Client { xml }))
            }
            if let Some(m) = m.subcommand_matches("repo-res") {
                let handle = Handle::from(m.value_of("handle").unwrap());
                command = Command::Rfc8181(Rfc8181Command::RepoRes(handle));
            }
        }

        let server = matches.value_of("server").unwrap(); // required
        let server = uri::Https::from_str(server).map_err(Error::UriError)?;

        let token = Token::from(matches.value_of("token").unwrap());

        let mut format = ReportFormat::Default;
        if let Some(fmt) = matches.value_of("format") {
            format = ReportFormat::from_str(fmt)?;
        }

        Ok(Options {
            server,
            token,
            format,
            command,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    NotSet,
    Health,
    TrustAnchor(TrustAnchorCommand),
    CertAuth(CaCommand),
    Publishers(PublishersCommand),
    Rfc8181(Rfc8181Command),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum TrustAnchorCommand {
    Init,
    Show,
    Publish,
    AddChild(AddChildRequest),
    UpdateChild(Handle, UpdateChildRequest),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum CaCommand {
    AddParent(Handle, AddParentRequest),
    ChildRequest(Handle),
    Init(CertAuthInit),
    KeyRollInit(Handle),
    List,
    Show(Handle),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishersCommand {
    Add(AddPublisher),
    Details(String),
    Deactivate(String),
    List,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddPublisher {
    pub handle: Handle,
    pub base_uri: uri::Rsync,
    pub token: Token,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rfc8181Command {
    List,
    Add(AddRfc8181Client),
    RepoRes(Handle),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddRfc8181Client {
    pub xml: PathBuf,
}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    UriError(uri::Error),

    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "{}", _0)]
    ReportError(ReportError),

    #[display(fmt = "Invalid RFC8183 XML: {}", _0)]
    Rfc8183(rfc8183::Error),

    #[display(fmt = "Invalid resources requested: {}", _0)]
    ResSetErr(ResSetErr),
}

impl From<rfc8183::Error> for Error {
    fn from(e: rfc8183::Error) -> Self {
        Error::Rfc8183(e)
    }
}

impl From<uri::Error> for Error {
    fn from(e: uri::Error) -> Self {
        Error::UriError(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<ReportError> for Error {
    fn from(e: ReportError) -> Self {
        Error::ReportError(e)
    }
}

impl From<ResSetErr> for Error {
    fn from(e: ResSetErr) -> Self {
        Error::ResSetErr(e)
    }
}
