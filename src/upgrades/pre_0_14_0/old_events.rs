use std::fmt;

use rpki::{
    ca::{
        idexchange::{ChildHandle, ParentHandle},
        provisioning::{
            IssuanceRequest, ParentResourceClassName, ResourceClassName,
            RevocationRequest,
        },
    },
    crypto::KeyIdentifier,
    repository::resources::ResourceSet,
};

use crate::{
    commons::api::{
        BgpSecAsnKey, CustomerAsn, IdCertInfo, ParentCaContact, ReceivedCert,
        RepositoryContact, RtaName,
    },
    daemon::ca::{
        BgpSecCertificateUpdates, CertAuthEvent, CertifiedKey,
        ChildCertificateUpdates, PreparedRta, Rfc8183Id,
        RoaPayloadJsonMapKey, RoaUpdates, SignedRta, StoredBgpSecCsr,
    },
};

use super::{
    Pre0_14_0AspaDefinition, Pre0_14_0AspaObjectsUpdates,
    Pre0_14_0AspaProvidersUpdate,
};

//------------ Pre0_14_0CertAuthEvent ---------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum Pre0_14_0CertAuthEvent {
    // Being a parent Events
    /// A child was added to this (parent) CA
    ChildAdded {
        child: ChildHandle,
        id_cert: IdCertInfo,
        resources: ResourceSet,
    },

    /// A certificate was issued to the child of this (parent) CA
    ChildCertificateIssued {
        child: ChildHandle,
        resource_class_name: ResourceClassName,
        ki: KeyIdentifier,
    },

    /// A child key was revoked.
    ChildKeyRevoked {
        child: ChildHandle,
        resource_class_name: ResourceClassName,
        ki: KeyIdentifier,
    },

    /// Child certificates (for potentially multiple children) were updated
    /// under a CA resource class. I.e. child certificates were issued,
    /// removed, or suspended.
    ChildCertificatesUpdated {
        resource_class_name: ResourceClassName,
        updates: ChildCertificateUpdates,
    },
    ChildUpdatedIdCert {
        child: ChildHandle,
        id_cert: IdCertInfo,
    },
    ChildUpdatedResources {
        child: ChildHandle,
        resources: ResourceSet,
    },
    ChildUpdatedResourceClassNameMapping {
        child: ChildHandle,
        name_in_parent: ResourceClassName,
        name_for_child: ResourceClassName,
    },
    ChildRemoved {
        child: ChildHandle,
    },

    // (Un)Suspend a child events
    ChildSuspended {
        child: ChildHandle,
    },
    ChildUnsuspended {
        child: ChildHandle,
    },

    // Being a child Events
    IdUpdated {
        id: Rfc8183Id,
    },
    ParentAdded {
        parent: ParentHandle,
        contact: ParentCaContact,
    },
    ParentUpdated {
        parent: ParentHandle,
        contact: ParentCaContact,
    },
    ParentRemoved {
        parent: ParentHandle,
    },
    ResourceClassAdded {
        resource_class_name: ResourceClassName,
        parent: ParentHandle,
        parent_resource_class_name: ParentResourceClassName,
        pending_key: KeyIdentifier,
    },
    ResourceClassRemoved {
        resource_class_name: ResourceClassName,
        parent: ParentHandle,
        revoke_requests: Vec<RevocationRequest>,
    },
    CertificateRequested {
        resource_class_name: ResourceClassName,
        req: IssuanceRequest,
        ki: KeyIdentifier, // Also contained in request. Drop?
    },
    CertificateReceived {
        resource_class_name: ResourceClassName,
        rcvd_cert: ReceivedCert,
        ki: KeyIdentifier, // Also in received cert. Drop?
    },

    // Key life cycle
    KeyRollPendingKeyAdded {
        // A pending key is added to an existing resource class in order to
        // initiate a key roll. Note that there will be a separate
        // 'CertificateRequested' event for this key.
        resource_class_name: ResourceClassName,
        pending_key_id: KeyIdentifier,
    },
    KeyPendingToNew {
        // A pending key is marked as 'new' when it has received its (first)
        // certificate. This means that the key is staged and a mft
        // and crl will be published. According to RFC 6489 this key
        // should be staged for 24 hours before it is promoted to
        // become the active key. However, in practice this time can be
        // shortened.
        resource_class_name: ResourceClassName,
        new_key: CertifiedKey, /* pending key which received a certificate
                                * becomes 'new', i.e. it is staged. */
    },
    KeyPendingToActive {
        // When a new resource class is created it will have a single pending
        // key only which is promoted to become the active (current)
        // key for the resource class immediately after receiving its
        // first certificate. Technically this is not a roll, but a simple
        // first activation.
        resource_class_name: ResourceClassName,
        current_key: CertifiedKey, /* there was no current key, pending
                                    * becomes active without staging when
                                    * cert is received. */
    },
    KeyRollActivated {
        // When a 'new' key is activated (becomes current), the previous
        // current key will be marked as old and we will request its
        // revocation. Note that any current ROAs and/or
        // issued certificates will also be re-issued under the new 'current'
        // key. These changes are tracked in separate `RoasUpdated`
        // and `ChildCertificatesUpdated` events.
        resource_class_name: ResourceClassName,
        revoke_req: RevocationRequest,
    },
    KeyRollFinished {
        // The key roll is finished when the parent confirms that the old key
        // is revoked. We can remove it and stop publishing its mft
        // and crl.
        resource_class_name: ResourceClassName,
    },
    UnexpectedKeyFound {
        // This event is generated in case our parent reports keys to us that
        // we do not believe we have. This should not happen in
        // practice, but this is tracked so that we can recover from
        // this situation. We can request revocation for all these keys
        // and create new keys in the RC as needed.
        resource_class_name: ResourceClassName,
        revoke_req: RevocationRequest,
    },

    // Route Authorizations
    RouteAuthorizationAdded {
        // Tracks a single authorization (VRP) which is added. Note that (1)
        // a command to update ROAs can contain multiple changes in
        // which case multiple events will result, and (2) we do not
        // have a 'modify' event. Modifications of e.g. the
        // max length are expressed as a 'removed' and 'added' event in a
        // single transaction.
        auth: RoaPayloadJsonMapKey,
    },
    RouteAuthorizationComment {
        auth: RoaPayloadJsonMapKey,
        comment: Option<String>,
    },
    RouteAuthorizationRemoved {
        // Tracks a single authorization (VRP) which is removed. See remark
        // for RouteAuthorizationAdded.
        auth: RoaPayloadJsonMapKey,
    },
    RoasUpdated {
        // Tracks ROA *objects* which are (re-)issued in a resource class.
        resource_class_name: ResourceClassName,
        updates: RoaUpdates,
    },

    // ASPA
    AspaConfigAdded {
        aspa_config: Pre0_14_0AspaDefinition,
    },
    AspaConfigUpdated {
        customer: CustomerAsn,
        update: Pre0_14_0AspaProvidersUpdate,
    },
    AspaConfigRemoved {
        customer: CustomerAsn,
    },
    AspaObjectsUpdated {
        // Tracks ASPA *object* which are (re-)issued in a resource class.
        resource_class_name: ResourceClassName,
        updates: Pre0_14_0AspaObjectsUpdates,
    },

    // BGPSec
    BgpSecDefinitionAdded {
        key: BgpSecAsnKey,
        csr: StoredBgpSecCsr,
    },
    BgpSecDefinitionUpdated {
        key: BgpSecAsnKey,
        csr: StoredBgpSecCsr,
    },
    BgpSecDefinitionRemoved {
        key: BgpSecAsnKey,
    },
    BgpSecCertificatesUpdated {
        // Tracks the actual BGPSec certificates (re-)issued in a resource
        // class
        resource_class_name: ResourceClassName,
        updates: BgpSecCertificateUpdates,
    },

    // Publishing
    RepoUpdated {
        // Adds the repository contact for this CA so that publication can
        // commence, and certificates can be requested from parents.
        // Note: the CA can only start requesting certificates when
        // it knows which URIs it can use.
        contact: RepositoryContact,
    },

    // Rta
    //
    // NOTE RTA support is still experimental and incomplete.
    RtaSigned {
        // Adds a signed RTA. The RTA can be single signed, or it can
        // be a multi-signed RTA based on an existing 'PreparedRta'.
        name: RtaName,
        rta: SignedRta,
    },
    RtaPrepared {
        // Adds a 'prepared' RTA. I.e. the context of keys which need to be
        // included in a multi-signed RTA.
        name: RtaName,
        prepared: PreparedRta,
    },
}

impl fmt::Display for Pre0_14_0CertAuthEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<Pre0_14_0CertAuthEvent> for CertAuthEvent {
    fn from(old: Pre0_14_0CertAuthEvent) -> CertAuthEvent {
        // Essentially, we can map everything one to one, except
        // for Aspa events which we will not migrate.
        match old {
            Pre0_14_0CertAuthEvent::AspaConfigAdded { .. } => unimplemented!("not migrated"),
            Pre0_14_0CertAuthEvent::AspaConfigUpdated { .. } => unimplemented!("not migrated"),
            Pre0_14_0CertAuthEvent::AspaConfigRemoved { .. } => unimplemented!("not migrated"),
            Pre0_14_0CertAuthEvent::AspaObjectsUpdated { .. } => unimplemented!("not migrated"),

            // The remaining events are mapped one to one
            Pre0_14_0CertAuthEvent::ChildAdded {
                child,
                id_cert,
                resources,
            } => CertAuthEvent::ChildAdded {
                child,
                id_cert,
                resources,
            },
            Pre0_14_0CertAuthEvent::ChildCertificateIssued {
                child,
                resource_class_name,
                ki,
            } => CertAuthEvent::ChildCertificateIssued {
                child,
                resource_class_name,
                ki,
            },
            Pre0_14_0CertAuthEvent::ChildKeyRevoked {
                child,
                resource_class_name,
                ki,
            } => CertAuthEvent::ChildKeyRevoked {
                child,
                resource_class_name,
                ki,
            },
            Pre0_14_0CertAuthEvent::ChildCertificatesUpdated {
                resource_class_name,
                updates,
            } => CertAuthEvent::ChildCertificatesUpdated {
                resource_class_name,
                updates,
            },
            Pre0_14_0CertAuthEvent::ChildUpdatedIdCert { child, id_cert } => {
                CertAuthEvent::ChildUpdatedIdCert { child, id_cert }
            }
            Pre0_14_0CertAuthEvent::ChildUpdatedResources { child, resources } => {
                CertAuthEvent::ChildUpdatedResources { child, resources }
            }
            Pre0_14_0CertAuthEvent::ChildUpdatedResourceClassNameMapping {
                child,
                name_in_parent,
                name_for_child,
            } => CertAuthEvent::ChildUpdatedResourceClassNameMapping {
                child,
                name_in_parent,
                name_for_child,
            },
            Pre0_14_0CertAuthEvent::ChildRemoved { child } => CertAuthEvent::ChildRemoved { child },
            Pre0_14_0CertAuthEvent::ChildSuspended { child } => CertAuthEvent::ChildSuspended { child },
            Pre0_14_0CertAuthEvent::ChildUnsuspended { child } => CertAuthEvent::ChildUnsuspended { child },
            Pre0_14_0CertAuthEvent::IdUpdated { id } => CertAuthEvent::IdUpdated { id },
            Pre0_14_0CertAuthEvent::ParentAdded { parent, contact } => CertAuthEvent::ParentAdded { parent, contact },
            Pre0_14_0CertAuthEvent::ParentUpdated { parent, contact } => {
                CertAuthEvent::ParentUpdated { parent, contact }
            }
            Pre0_14_0CertAuthEvent::ParentRemoved { parent } => CertAuthEvent::ParentRemoved { parent },
            Pre0_14_0CertAuthEvent::ResourceClassAdded {
                resource_class_name,
                parent,
                parent_resource_class_name,
                pending_key,
            } => CertAuthEvent::ResourceClassAdded {
                resource_class_name,
                parent,
                parent_resource_class_name,
                pending_key,
            },
            Pre0_14_0CertAuthEvent::ResourceClassRemoved {
                resource_class_name,
                parent,
                revoke_requests,
            } => CertAuthEvent::ResourceClassRemoved {
                resource_class_name,
                parent,
                revoke_requests,
            },
            Pre0_14_0CertAuthEvent::CertificateRequested {
                resource_class_name,
                req,
                ki,
            } => CertAuthEvent::CertificateRequested {
                resource_class_name,
                req,
                ki,
            },
            Pre0_14_0CertAuthEvent::CertificateReceived {
                resource_class_name,
                rcvd_cert,
                ki,
            } => CertAuthEvent::CertificateReceived {
                resource_class_name,
                rcvd_cert,
                ki,
            },
            Pre0_14_0CertAuthEvent::KeyRollPendingKeyAdded {
                resource_class_name,
                pending_key_id,
            } => CertAuthEvent::KeyRollPendingKeyAdded {
                resource_class_name,
                pending_key_id,
            },
            Pre0_14_0CertAuthEvent::KeyPendingToNew {
                resource_class_name,
                new_key,
            } => CertAuthEvent::KeyPendingToNew {
                resource_class_name,
                new_key,
            },
            Pre0_14_0CertAuthEvent::KeyPendingToActive {
                resource_class_name,
                current_key,
            } => CertAuthEvent::KeyPendingToActive {
                resource_class_name,
                current_key,
            },
            Pre0_14_0CertAuthEvent::KeyRollActivated {
                resource_class_name,
                revoke_req,
            } => CertAuthEvent::KeyRollActivated {
                resource_class_name,
                revoke_req,
            },
            Pre0_14_0CertAuthEvent::KeyRollFinished { resource_class_name } => {
                CertAuthEvent::KeyRollFinished { resource_class_name }
            }
            Pre0_14_0CertAuthEvent::UnexpectedKeyFound {
                resource_class_name,
                revoke_req,
            } => CertAuthEvent::UnexpectedKeyFound {
                resource_class_name,
                revoke_req,
            },
            Pre0_14_0CertAuthEvent::RouteAuthorizationAdded { auth } => CertAuthEvent::RouteAuthorizationAdded { auth },
            Pre0_14_0CertAuthEvent::RouteAuthorizationComment { auth, comment } => {
                CertAuthEvent::RouteAuthorizationComment { auth, comment }
            }
            Pre0_14_0CertAuthEvent::RouteAuthorizationRemoved { auth } => {
                CertAuthEvent::RouteAuthorizationRemoved { auth }
            }
            Pre0_14_0CertAuthEvent::RoasUpdated {
                resource_class_name,
                updates,
            } => CertAuthEvent::RoasUpdated {
                resource_class_name,
                updates,
            },

            Pre0_14_0CertAuthEvent::BgpSecDefinitionAdded { key, csr } => {
                CertAuthEvent::BgpSecDefinitionAdded { key, csr }
            }
            Pre0_14_0CertAuthEvent::BgpSecDefinitionUpdated { key, csr } => {
                CertAuthEvent::BgpSecDefinitionUpdated { key, csr }
            }
            Pre0_14_0CertAuthEvent::BgpSecDefinitionRemoved { key } => CertAuthEvent::BgpSecDefinitionRemoved { key },
            Pre0_14_0CertAuthEvent::BgpSecCertificatesUpdated {
                resource_class_name,
                updates,
            } => CertAuthEvent::BgpSecCertificatesUpdated {
                resource_class_name,
                updates,
            },
            Pre0_14_0CertAuthEvent::RepoUpdated { contact } => CertAuthEvent::RepoUpdated { contact },
            Pre0_14_0CertAuthEvent::RtaSigned { name, rta } => CertAuthEvent::RtaSigned { name, rta },
            Pre0_14_0CertAuthEvent::RtaPrepared { name, prepared } => CertAuthEvent::RtaPrepared { name, prepared },
        }
    }
}
