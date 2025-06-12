//! The events for the `CertAuth` aggregate.

use std::fmt;
use rpki::ca::idexchange::{ChildHandle, ParentHandle};
use rpki::ca::provisioning::{
    IssuanceRequest, ParentResourceClassName, ResourceClassName,
    RevocationRequest,
};
use rpki::crypto::KeyIdentifier;
use rpki::repository::resources::ResourceSet;
use serde::{Deserialize, Serialize};
use crate::api::admin::{ParentCaContact, RepositoryContact};
use crate::api::aspa::{
    AspaDefinition, AspaProvidersUpdate, CustomerAsn,
};
use crate::api::bgpsec::BgpSecAsnKey;
use crate::api::ca::{IdCertInfo, ReceivedCert, RtaName};
use crate::api::roa::RoaPayloadJsonMapKey;
use crate::commons::crypto::KrillSigner;
use crate::commons::error::KrillError;
use crate::commons::eventsourcing::{Event, InitEvent};
use super::aspa::AspaObjectsUpdates;
use super::bgpsec::{BgpSecCertificateUpdates, StoredBgpSecCsr};
use super::certauth::Rfc8183Id;
use super::child::ChildCertificateUpdates;
use super::keys::CertifiedKey;
use super::roa::RoaUpdates;
use super::rta::{PreparedRta, SignedRta};


//------------ CertAuthInitEvent ---------------------------------------------

/// The init event of the `CertAuth` aggregate.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertAuthInitEvent {
    /// The ID certificate used by the CA for communication.
    pub id: Rfc8183Id,
}

impl InitEvent for CertAuthInitEvent {}

impl CertAuthInitEvent {
    /// Creates a new init event with a new ID certificate from the signer.
    pub fn init(
        signer: &KrillSigner
    ) -> Result<CertAuthInitEvent, KrillError> {
        Rfc8183Id::generate(signer).map(|id| CertAuthInitEvent { id })
    }
}

impl fmt::Display for CertAuthInitEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Initialized with ID key hash: {}",
            self.id.cert().public_key.key_identifier()
        )?;
        Ok(())
    }
}


//------------ CertAuthEvent ------------------------------------------------

/// The events of the `CertAuth` aggregate.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum CertAuthEvent {
    //---  Child events
    //
    // These events relate to the children of a CA. I.e., this is about the
    // CA being a parent.

    /// A child was added to this CA.
    ChildAdded {
        /// The local handle of the child CA.
        child: ChildHandle,

        /// The ID certificate of the child CA.
        id_cert: IdCertInfo,

        /// The set of resources set the child CA is entitled to.
        resources: ResourceSet,
    },

    /// A certificate was issued to the a child of this CA.
    ChildCertificateIssued {
        /// The local handle the child CA in question.
        child: ChildHandle,

        /// The local name of the resource class the certificate is for.
        resource_class_name: ResourceClassName,

        /// The identifier of the key being certified.
        ki: KeyIdentifier,
    },

    /// A child CA’s key was revoked.
    ChildKeyRevoked {
        /// The local handle the child CA in question.
        child: ChildHandle,

        /// The local name of the resource class the certificate is for.
        resource_class_name: ResourceClassName,

        /// The identifier of the key being certified.
        ki: KeyIdentifier,
    },

    /// Child certificates were updated under a resource class.
    ChildCertificatesUpdated {
        /// The resource class for which the updates are for.
        resource_class_name: ResourceClassName,

        /// The updates.
        updates: ChildCertificateUpdates,
    },

    /// A child’s ID certificate was updated.
    ChildUpdatedIdCert {
        /// The local handle the child CA in question.
        child: ChildHandle,

        /// The new ID certificate of the child.
        id_cert: IdCertInfo,
    },

    /// The resources a child CA is entitled to have been updated.
    ChildUpdatedResources {
        /// The local handle the child CA in question.
        child: ChildHandle,

        /// The new resource set the child CA is entitled to.
        resources: ResourceSet,
    },

    /// The resource class mapping for a child CA was updated.
    ChildUpdatedResourceClassNameMapping {
        /// The local handle the child CA in question.
        child: ChildHandle,

        /// The resource class name in the parent.
        name_in_parent: ResourceClassName,

        /// The resource class name in the child.
        name_for_child: ResourceClassName,
    },

    /// A child CA was removed.
    ChildRemoved {
        /// The local handle the child CA in question.
        child: ChildHandle,
    },

    /// A child CA was suspended.
    ChildSuspended {
        /// The local handle the child CA in question.
        child: ChildHandle,
    },

    /// The suspension of a child CA was lifted.
    ChildUnsuspended {
        /// The local handle the child CA in question.
        child: ChildHandle,
    },

    
    //--- Parent events.
    //
    // These events relate to the parents of a CA. I.e., this is about the
    // CA being a child.

    /// The ID certificate of the CA was updated.
    IdUpdated {
        /// The new ID certificate.
        id: Rfc8183Id,
    },

    /// A parent CA was added to the CA.
    ParentAdded {
        /// The local handle of the parent CA.
        parent: ParentHandle,

        /// Information about how to communicate with the parent CA.
        contact: ParentCaContact,
    },

    /// Contact information for the parent CA was updated.
    ParentUpdated {
        /// The local handle of the parent CA.
        parent: ParentHandle,

        /// The new information on how to communicate with the parent CA.
        contact: ParentCaContact,
    },

    /// A parent CA was removed from the CA.
    ParentRemoved {
        /// The local handle of the parent CA.
        parent: ParentHandle,
    },

    /// A resource class was added by a parent CA.
    ResourceClassAdded {
        /// The local name of the resource class.
        resource_class_name: ResourceClassName,

        /// The local handle of the parent CA.
        parent: ParentHandle,

        /// The name of the resource class in the parent CA.
        parent_resource_class_name: ParentResourceClassName,

        /// The CA key we want to use for the resource class.
        pending_key: KeyIdentifier,
    },

    /// A resource class was removed by the parent CA.
    ResourceClassRemoved {
        /// The local name of the resource class.
        resource_class_name: ResourceClassName,

        /// The local handle of the parent CA.
        parent: ParentHandle,

        /// The request to revoke the certficate for the resource class.
        revoke_requests: Vec<RevocationRequest>,
    },

    /// A certficate for a resource class was requested from the parent.
    CertificateRequested {
        /// The local name of the resource class.
        resource_class_name: ResourceClassName,

        /// The request for the certificate sent to the parent.
        req: IssuanceRequest,

        /// The identifier for the key for which the certificate was requested.
        //
        //  XXX Also contained in request. Drop?
        ki: KeyIdentifier,
    },

    /// A certificate for a resource class was received from the parent.
    CertificateReceived {
        /// The local name of the resource class.
        resource_class_name: ResourceClassName,

        /// The certificate that was received.
        rcvd_cert: ReceivedCert,

        /// The identifier for the key for which the certificate was received.
        //
        //  XXX Also contained in request. Drop?
        ki: KeyIdentifier, // Also in received cert. Drop?
    },


    //--- Key life cycle

    /// A pending key was added to an exsiting resource class.
    ///
    /// This initiates a key roll. Note that there will be a separate
    /// [`CertificateRequested`][Self::CertificateRequested] event for this
    /// key.
    KeyRollPendingKeyAdded {
        /// The local name of the resource class to which the key was added..
        resource_class_name: ResourceClassName,

        /// The identifier of the key that was added.
        pending_key_id: KeyIdentifier,
    },

    /// A pending key was marked as new after it had received a certificate.
    ///
    /// This means that the key is staged and a mft and crl will be published.
    /// According to RFC 6489 this key should be staged for 24 hours before
    /// it is promoted to become the active key. However, in practice this
    /// time can be shortened.
    KeyPendingToNew {
        /// The local name of the resource class the event relates to.
        resource_class_name: ResourceClassName,

        /// Information about the key including its certificate.
        new_key: CertifiedKey,
    },

    /// A pending key has become the active key without being staged first.
    ///
    /// When a new resource class is created it will have a single pending
    /// key only which is promoted to become the active (current)
    /// key for the resource class immediately after receiving its
    /// first certificate. Technically this is not a roll, but a simple
    /// first activation.
    KeyPendingToActive {
        /// The local name of the resource class the event relates to.
        resource_class_name: ResourceClassName,

        /// Information about the now active key.
        current_key: CertifiedKey,
    },

    /// During a key roll, a new key has been activated.
    ///
    /// When a 'new' key is activated, i.e., it becomes the current key,
    /// the previous current key will be marked as old and we will request
    /// its revocation. Note that any current ROAs and/or issued certificates
    /// will also be re-issued under the new 'current' key. These changes are
    /// tracked in separate
    /// [`RoasUpdated`][Self::RoasUpdated] and
    /// [`ChildCertificatesUpdated`][Self::ChildCertificatesUpdated] events.
    KeyRollActivated {
        /// The local name of the resource class the event relates to.
        resource_class_name: ResourceClassName,

        /// The revocation request for the previous active key.
        revoke_req: RevocationRequest,
    },

    /// A key roll has been finished.
    ///
    /// The key roll is finished when the parent confirms that the old key
    /// is revoked. We can remove it and stop publishing its manifest and
    /// CRL.
    KeyRollFinished {
        /// The resource class for which the key roll has finished.
        resource_class_name: ResourceClassName,
    },

    /// An unknown key was returned in a parent exchange.
    /// This event is generated in case our parent reports keys to us that
    /// we do not believe we have. This should not happen in practice, but
    /// this is tracked so that we can recover from this situation. We can
    /// request revocation for all these keys and create new keys in the RC
    /// as needed.
    UnexpectedKeyFound {
        /// The resource class for which the key was found..
        resource_class_name: ResourceClassName,

        /// A revocation request for this key.
        revoke_req: RevocationRequest,
    },


    //--- Route authorizations

    /// A route authorization was added.
    ///
    /// Tracks a single authorization (VRP) which is added. Note that (1)
    /// a command to update ROAs can contain multiple changes in which case
    /// multiple events will result, and (2) we do not have a 'modify' event.
    /// Modifications of e.g. the max length are expressed as separate
    /// 'removed' and 'added' events within a single stored command.
    RouteAuthorizationAdded {
        /// The ROA payload of the authorization to be added.
        auth: RoaPayloadJsonMapKey,
    },

    /// A comment was changed for a route authorization.
    RouteAuthorizationComment {
        /// The ROA payload of the authorization.
        auth: RoaPayloadJsonMapKey,

        /// The optional comment for the authorization.
        comment: Option<String>,
    },

    /// A route authorization was removed.
    ///
    /// Tracks a single authorization (VRP) which is removed. See the
    /// remark for [`RouteAuthorizationAdded`][Self::RouteAuthorizationAdded].
    RouteAuthorizationRemoved {
        /// The ROA payload of the authorization to be removed.
        auth: RoaPayloadJsonMapKey,
    },

    /// The set of ROA objects for a resource class has been updated.
    RoasUpdated {
        /// The resource class for which the ROA objects are updated.
        resource_class_name: ResourceClassName,

        /// The updates to be made.
        updates: RoaUpdates,
    },

    //--- ASPA

    /// A new ASPA configuration has been added.
    AspaConfigAdded {
        /// The ASPA configuration that should be added.
        aspa_config: AspaDefinition,
    },

    /// An ASPA configuration has been updated.
    AspaConfigUpdated {
        /// The customer ASN of the ASPA configuration to be updated.
        customer: CustomerAsn,

        /// The update to the provider ASNs of the ASPA.
        update: AspaProvidersUpdate,
    },

    /// An ASPA configuration has been removed.
    AspaConfigRemoved {
        /// The customer ASN of the ASPA configuration to be removed.
        customer: CustomerAsn,
    },

    /// The set of ASPA objects for a resource class has changed.
    AspaObjectsUpdated {
        /// The resource class for which the ASPA objects have changed.
        resource_class_name: ResourceClassName,

        /// The changes to the ASPA objects.
        updates: AspaObjectsUpdates,
    },

    //--- BGPsec router keys

    /// A BGPsec router key definition was added.
    BgpSecDefinitionAdded {
        /// The ASN and key identifier for the router key to be added.
        key: BgpSecAsnKey,

        /// The certificate signing request for the router key.
        csr: StoredBgpSecCsr,
    },

    /// A BGPsec router key definition has been updated.
    BgpSecDefinitionUpdated {
        /// The ASN and key identifier for the router key to be added.
        key: BgpSecAsnKey,

        /// The certificate signing request for the router key.
        csr: StoredBgpSecCsr,
    },

    /// A BGPsec router key definition has been removed.
    BgpSecDefinitionRemoved {
        /// The ASN and key identifier for the router key to be added.
        key: BgpSecAsnKey,
    },

    /// The set of BGPset certificates for a resourc class class has changed.
    BgpSecCertificatesUpdated {
        /// The resource class for which BGPsec certificates have changed.
        resource_class_name: ResourceClassName,

        /// The changes to the BGPsec certificates.
        updates: BgpSecCertificateUpdates,
    },

    //--- Publishing

    /// A respository contact was added for this CA.
    ///
    /// A repository contact is necessary for publication to commence. Because
    /// communication with the repository is necessary to learn the URIs to
    /// use in objects, a CA can only start requesting certificates from its
    /// parents once it has a repository contact and successfully used it.
    RepoUpdated {
        /// The repository contact information.
        contact: RepositoryContact,
    },

    //--- Rta
    //
    // Note: RTA support is deprecated and will be removed.

    /// A signed RTA was added.
    ///
    /// The RTA can be single signed, or it can be a multi-signed RTA based
    /// on an existing 'PreparedRta'.
    RtaSigned {
        /// The name of the signed RTA.
        name: RtaName,

        /// The signed RTA.
        rta: SignedRta,
    },

    /// A “prepared” RTA was added.
    ///
    /// This declares the context of keys which need to be included in a
    /// multi-signed RTA.
    RtaPrepared {
        /// The name of the signed RTA.
        name: RtaName,

        /// Information about the prepared RTA.
        prepared: PreparedRta,
    },
}

impl Event for CertAuthEvent {}

impl fmt::Display for CertAuthEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CertAuthEvent::ChildAdded {
                child,
                id_cert,
                resources,
            } => {
                write!(
                    f,
                    "added child '{}' with resources '{}, id (hash): {}",
                    child,
                    resources,
                    id_cert.public_key.key_identifier()
                )
            }
            CertAuthEvent::ChildCertificateIssued {
                child,
                resource_class_name,
                ki,
            } => write!(
                f,
                "issued certificate to child '{}' for class '{}' and \
                 pub key '{}'",
                child, resource_class_name, ki
            ),
            CertAuthEvent::ChildCertificatesUpdated {
                resource_class_name,
                updates,
            } => {
                write!(
                    f,
                    "updated child certificates in resource class {}",
                    resource_class_name
                )?;
                if !updates.issued.is_empty() {
                    write!(f, " issued keys: ")?;
                    for iss in &updates.issued {
                        write!(f, " {}", iss.key_identifier())?;
                    }
                }
                if !updates.removed.is_empty() {
                    write!(f, " revoked keys: ")?;
                    for rev in &updates.removed {
                        write!(f, " {}", rev)?;
                    }
                }
                if !updates.suspended.is_empty() {
                    write!(f, " suspended keys: ")?;
                    for cert in &updates.suspended {
                        write!(f, " {}", cert.key_identifier())?;
                    }
                }
                if !updates.unsuspended.is_empty() {
                    write!(f, " unsuspended keys: ")?;
                    for cert in &updates.unsuspended {
                        write!(f, " {}", cert.key_identifier())?;
                    }
                }

                Ok(())
            }
            CertAuthEvent::ChildKeyRevoked {
                child,
                resource_class_name,
                ki,
            } => write!(
                f,
                "revoked certificate for child '{}' in resource class \
                 '{}' with key(hash) '{}'",
                child, resource_class_name, ki
            ),
            CertAuthEvent::ChildUpdatedIdCert { child, id_cert } => {
                write!(
                    f,
                    "updated child '{}' id (hash) '{}'",
                    child,
                    id_cert.public_key.key_identifier()
                )
            }
            CertAuthEvent::ChildUpdatedResources { child, resources } => {
                write!(f,
                    "updated child '{}' resources to '{}'", child, resources
                )
            }
            CertAuthEvent::ChildUpdatedResourceClassNameMapping {
                child,
                name_in_parent,
                name_for_child,
            } => {
                write!(
                    f,
                    "updated child '{}' map parent RC name '{}' to '{}' \
                     for child",
                    child, name_in_parent, name_for_child
                )
            }

            CertAuthEvent::ChildRemoved { child } => {
                write!(f, "removed child '{}'", child)
            }
            CertAuthEvent::ChildSuspended { child } => {
                write!(f, "suspended child '{}'", child)
            }
            CertAuthEvent::ChildUnsuspended { child } => {
                write!(f, "unsuspended child '{}'", child)
            }
            CertAuthEvent::IdUpdated { id } => write!(
                f,
                "updated RFC8183 id to key '{}'",
                id.cert().public_key.key_identifier()
            ),
            CertAuthEvent::ParentAdded { parent, .. } => {
                write!(f, "added parent '{}' ", parent)
            }
            CertAuthEvent::ParentUpdated { parent, .. } => {
                write!(f, "updated parent '{}'", parent)
            }
            CertAuthEvent::ParentRemoved { parent } => {
                write!(f, "removed parent '{}'", parent)
            }
            CertAuthEvent::ResourceClassAdded {
                resource_class_name, ..
            } => {
                write!(f,
                    "added resource class with name '{}'",
                    resource_class_name
                )
            }
            CertAuthEvent::ResourceClassRemoved {
                resource_class_name,
                parent,
                ..
            } => {
                write!(f,
                    "removed resource class with name '{}' under parent '{}'",
                    resource_class_name, parent
                )
            }
            CertAuthEvent::CertificateRequested {
                resource_class_name,
                ki,
                ..
            } => {
                write!(f,
                    "requested certificate for key (hash) '{}' under \
                     resource class '{}'",
                    ki, resource_class_name
                )
            }
            CertAuthEvent::CertificateReceived {
                resource_class_name,
                ki,
                ..
            } => {
                write!(f,
                    "received certificate for key (hash) '{}' under \
                     resource class '{}'",
                    ki, resource_class_name
                )
            }
            CertAuthEvent::KeyRollPendingKeyAdded {
                resource_class_name,
                pending_key_id,
            } => {
                write!(
                    f,
                    "key roll: added pending key '{}' under resource class \
                    '{}'",
                    pending_key_id, resource_class_name
                )
            }
            CertAuthEvent::KeyPendingToNew {
                resource_class_name,
                new_key,
            } => {
                write!(f,
                    "key roll: moving pending key '{}' to new state under \
                    resource class '{}'",
                    new_key.key_id(), resource_class_name
                )
            }
            CertAuthEvent::KeyPendingToActive {
                resource_class_name,
                current_key,
            } => {
                write!(f,
                    "activating pending key '{}' under resource class '{}'",
                    current_key.key_id(),
                    resource_class_name
                )
            }
            CertAuthEvent::KeyRollActivated {
                resource_class_name,
                revoke_req,
            } => {
                write!(f,
                    "key roll: activated new key, requested revocation of \
                     '{}' under resource class '{}'",
                    revoke_req.key(), resource_class_name
                )
            }
            CertAuthEvent::KeyRollFinished { resource_class_name } => {
                write!(f,
                    "key roll: finished for resource class '{}'",
                    resource_class_name
                )
            }
            CertAuthEvent::UnexpectedKeyFound {
                resource_class_name,
                revoke_req,
            } => {
                write!(f,
                    "Found unexpected key in resource class '{}', will try \
                     to revoke key id: '{}'",
                    resource_class_name, revoke_req.key()
                )
            }
            CertAuthEvent::RouteAuthorizationAdded { auth } => {
                write!(f, "added ROA: '{}'", auth)
            }
            CertAuthEvent::RouteAuthorizationComment { auth, comment } => {
                if let Some(comment) = comment {
                    write!(f,
                        "added comment to ROA: '{}' => {}",
                        auth, comment
                    )
                }
                else {
                    write!(f, "removed comment from ROA: '{}'", auth)
                }
            }
            CertAuthEvent::RouteAuthorizationRemoved { auth } => {
                write!(f, "removed ROA: '{}'", auth)
            }
            CertAuthEvent::RoasUpdated {
                resource_class_name,
                updates,
            } => {
                write!(f,
                    "updated ROA objects under resource class '{}'",
                    resource_class_name
                )?;
                updates.fmt_event(f)
            }
            CertAuthEvent::AspaConfigAdded { aspa_config: addition } => {
                write!(f, "{}", addition)
            }
            CertAuthEvent::AspaConfigUpdated { customer, update } => {
                write!(f,
                    "updated ASPA config for customer ASN: {} {}",
                    customer, update
                )
            }
            CertAuthEvent::AspaConfigRemoved { customer } => {
                write!(f,
                    "removed ASPA config for customer ASN: {}",
                    customer
                )
            }
            CertAuthEvent::AspaObjectsUpdated {
                resource_class_name,
                updates,
            } => {
                write!(f,
                    "updated ASPA objects under resource class '{}'{}",
                    resource_class_name, updates,
                )
            }
            CertAuthEvent::BgpSecDefinitionAdded { key, .. } => {
                write!(
                    f,
                    "added BGPSec definition for ASN: {} and key id: {}",
                    key.asn, key.key
                )
            }
            CertAuthEvent::BgpSecDefinitionUpdated { key, .. } => {
                write!(
                    f,
                    "updated CSR for BGPSec definition for ASN: {} and \
                    key id: {}",
                    key.asn, key.key,
                )
            }
            CertAuthEvent::BgpSecDefinitionRemoved { key } => {
                write!(
                    f,
                    "removed BGPSec definition for ASN: {} and key id: {}",
                    key.asn, key.key,
                )
            }
            CertAuthEvent::BgpSecCertificatesUpdated {
                resource_class_name,
                updates,
            } => {
                write!(f,
                    "updated BGPSec certificates under resource class \
                    '{resource_class_name}{updates}'",
                )
            }
            CertAuthEvent::RepoUpdated { contact } => {
                write!(
                    f,
                    "updated repository to remote server: {}",
                    contact.server_info.service_uri
                )
            }
            CertAuthEvent::RtaPrepared { name, prepared } => {
                write!(f,
                    "Prepared RTA '{}' for resources: {}",
                    name, prepared.resources()
                )
            }
            CertAuthEvent::RtaSigned { name, rta } => {
                write!(f,
                    "Signed RTA '{}' for resources: {}",
                    name, rta.resources()
                )
            }
        }
    }
}

