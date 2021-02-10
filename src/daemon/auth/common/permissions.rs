#[allow(non_camel_case_types)]
#[derive(Clone, PartialEq)]
pub enum Permission {
    LOGIN,
    PUB_ADMIN,
    PUB_LIST,
    PUB_READ,
    PUB_CREATE,
    PUB_DELETE,
    CA_LIST,
    CA_READ,
    CA_CREATE,
    CA_UPDATE,
    ROUTES_READ,
    ROUTES_UPDATE,
    ROUTES_ANALYSIS,
    RTA_LIST,
    RTA_READ,
    RTA_UPDATE,
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Permission::LOGIN => write!(f, "LOGIN"),
            Permission::PUB_ADMIN => write!(f, "PUB_ADMIN"),
            Permission::PUB_LIST => write!(f, "PUB_LIST"),
            Permission::PUB_READ => write!(f, "PUB_READ"),
            Permission::PUB_CREATE => write!(f, "PUB_CREATE"),
            Permission::PUB_DELETE => write!(f, "PUB_DELETE"),
            Permission::CA_LIST => write!(f, "CA_LIST"),
            Permission::CA_READ => write!(f, "CA_READ"),
            Permission::CA_CREATE => write!(f, "CA_CREATE"),
            Permission::CA_UPDATE => write!(f, "CA_UPDATE"),
            Permission::ROUTES_READ => write!(f, "ROUTES_READ"),
            Permission::ROUTES_UPDATE => write!(f, "ROUTES_UPDATE"),
            Permission::ROUTES_ANALYSIS => write!(f, "ROUTES_ANALYSIS"),
            Permission::RTA_LIST => write!(f, "RTA_LIST"),
            Permission::RTA_READ => write!(f, "RTA_READ"),
            Permission::RTA_UPDATE => write!(f, "RTA_UPDATE"),
        }
    }
}

impl std::str::FromStr for Permission {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "LOGIN" => Ok(Permission::LOGIN),
            "PUB_ADMIN" => Ok(Permission::PUB_ADMIN),
            "PUB_LIST" => Ok(Permission::PUB_LIST),
            "PUB_READ" => Ok(Permission::PUB_READ),
            "PUB_CREATE" => Ok(Permission::PUB_CREATE),
            "PUB_DELETE" => Ok(Permission::PUB_DELETE),
            "CA_LIST" => Ok(Permission::CA_LIST),
            "CA_READ" => Ok(Permission::CA_READ),
            "CA_CREATE" => Ok(Permission::CA_CREATE),
            "CA_UPDATE" => Ok(Permission::CA_UPDATE),
            "ROUTES_READ" => Ok(Permission::ROUTES_READ),
            "ROUTES_UPDATE" => Ok(Permission::ROUTES_UPDATE),
            "ROUTES_ANALYSIS" => Ok(Permission::ROUTES_ANALYSIS),
            "RTA_LIST" => Ok(Permission::RTA_LIST),
            "RTA_READ" => Ok(Permission::RTA_READ),
            "RTA_UPDATE" => Ok(Permission::RTA_UPDATE),
            _ => Err(format!("Unknown permission '{}'", input))
        }
    }
}