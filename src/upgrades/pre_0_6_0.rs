//! Responsible for migrating commands predating Krill v0.6.0
use std::collections::{BTreeMap, HashSet};
use std::convert::TryFrom;
use std::str::FromStr;

use rpki::crypto::KeyIdentifier;
use rpki::x509::Time;

use crate::commons::api::{
    Handle, RequestResourceLimit, ResourceClassName, ResourceSet, RevocationRequest, RoaDefinition,
    RoaDefinitionUpdates, StorableCaCommand, StorableParentContact, StorableRepositoryCommand,
    StoredEffect,
};
use crate::commons::eventsourcing::{
    Aggregate, KeyStore, KeyStoreError, KeyStoreVersion, StoredCommand, StoredValueInfo,
};
use crate::commons::remote::rfc8183::ServiceUri;
use crate::commons::util::softsigner::OpenSslSigner;
use crate::daemon::ca::CertAuth;
use crate::pubd::Repository;
use crate::upgrades::{UpgradeError, UpgradeStore};

//------------ UpgradeCas --------------------------------------------------

pub struct UpgradeCas;

impl UpgradeStore for UpgradeCas {
    fn needs_migrate<S: KeyStore>(&self, store: &S) -> Result<bool, UpgradeError> {
        match store.get_version() {
            Ok(version) => match version {
                KeyStoreVersion::Pre0_6 => Ok(true),
                _ => Ok(false),
            },
            Err(e) => match e {
                KeyStoreError::NotInitialised => Ok(false),
                _ => Err(UpgradeError::KeyStoreError(e)),
            },
        }
    }

    fn migrate<S: KeyStore>(&self, store: &S) -> Result<(), UpgradeError> {
        if self.needs_migrate(store)? {
            // For each aggregate
            for ca_handle in store.aggregates() {
                //   Find all commands keys and migrate them
                let mut seq = 1;

                let mut last_command = 1;
                let mut last_update: Time = Time::now();

                let keys = store.keys_ascending(&ca_handle, ".cmd");
                info!("Migrating {} commands for CA: {}", keys.len(), ca_handle);

                for old_key in keys {
                    // Parse as PreviousCommand
                    if let Some(previous) = store.get::<PreviousCommand>(&ca_handle, &old_key)? {
                        // Convert to new command, save it, remove the old command and increase the sequence
                        let previous = previous.with_handle(ca_handle.clone());
                        let command = previous.into_new_stored_ca_command(seq)?;
                        last_update = command.time();
                        store.store_command(command)?;
                        store.drop(&ca_handle, &old_key)?;
                        last_command = seq;
                        seq += 1;
                    }

                    if seq % 100 == 0 {
                        info!(".. {} done", seq)
                    }
                }
                info!("Done migrating commands for CA: {}", ca_handle);

                info!("Regenerating latest snapshot, this can take a moment");
                // Load CA, then save a new snapshot and info for the CA
                let ca: CertAuth<OpenSslSigner> = store
                    .get_aggregate(&ca_handle)
                    .map_err(|e| {
                        UpgradeError::Custom(format!(
                            "Cannot load ca '{}' error: {}",
                            ca_handle.clone(),
                            e
                        ))
                    })?
                    .ok_or_else(|| UpgradeError::CannotLoadAggregate(ca_handle.clone()))?;

                store.store_snapshot(&ca_handle, &ca)?;

                let info = StoredValueInfo {
                    snapshot_version: ca.version(),
                    last_event: ca.version(),
                    last_command,
                    last_update,
                };
                store.save_info(&ca_handle, &info)?;
                info!("Saved updated snapshot for CA: {}", ca_handle);
            }

            store.set_version(&KeyStoreVersion::V0_6)?;
            info!("Finished migrating commands");
            Ok(())
        } else {
            Ok(())
        }
    }
}

//------------ UpgradePubd -------------------------------------------------

pub struct UpgradePubd;

impl UpgradeStore for UpgradePubd {
    fn needs_migrate<S: KeyStore>(&self, store: &S) -> Result<bool, UpgradeError> {
        if store.aggregates().is_empty() {
            Ok(false)
        } else {
            match store.get_version() {
                Ok(version) => match version {
                    KeyStoreVersion::Pre0_6 => Ok(true),
                    _ => Ok(false),
                },
                Err(e) => match e {
                    KeyStoreError::NotInitialised => Ok(false),
                    _ => Err(UpgradeError::KeyStoreError(e)),
                },
            }
        }
    }

    fn migrate<S: KeyStore>(&self, store: &S) -> Result<(), UpgradeError> {
        if self.needs_migrate(store)? {
            // For each aggregate
            for pubd_handle in store.aggregates() {
                //   Find all commands keys and migrate them
                let mut seq = 1;

                let mut last_command = 1;
                let mut last_update: Time = Time::now();
                let keys = store.keys_ascending(&pubd_handle, ".cmd");

                info!("Migrating {} commands for Repository server", keys.len());

                for old_key in keys {
                    // Parse as PreviousCommand
                    if let Some(previous) = store.get::<PreviousCommand>(&pubd_handle, &old_key)? {
                        // Convert to new command, save it, remove the old command and increase the sequence
                        let previous = previous.with_handle(pubd_handle.clone());
                        let command = previous.into_new_stored_pubd_command(seq)?;
                        last_update = command.time();
                        store.store_command(command)?;
                        store.drop(&pubd_handle, &old_key)?;
                        last_command = seq;
                        seq += 1;
                    }
                }

                info!("Done migrating commands for Repository server");

                info!("Regenerating repository and stats, this can take a moment");
                // Load CA, then save a new snapshot and info for the CA
                let mut repository: Repository = store
                    .get_aggregate(&pubd_handle)
                    .map_err(|e| {
                        UpgradeError::Custom(format!(
                            "Cannot load ca '{}' error: {}",
                            pubd_handle.clone(),
                            e
                        ))
                    })?
                    .ok_or_else(|| UpgradeError::CannotLoadAggregate(pubd_handle.clone()))?;

                repository.regenerate_stats();

                store.store_snapshot(&pubd_handle, &repository)?;
                info!("Saved updated snapshot for Repository server");

                let info = StoredValueInfo {
                    snapshot_version: repository.version(),
                    last_event: repository.version(),
                    last_command,
                    last_update,
                };
                store.save_info(&pubd_handle, &info)?;
            }

            store.set_version(&KeyStoreVersion::V0_6)?;
            Ok(())
        } else {
            Ok(())
        }
    }
}

//------------ PreviousCommand ---------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PreviousCommand {
    actor: String,
    time: Time,
    handle: Handle,
    version: u64,
    summary: String,
    effect: StoredEffect,
}

impl PreviousCommand {
    fn with_handle(mut self, handle: Handle) -> Self {
        self.handle = handle;
        self
    }

    fn into_new_stored_ca_command(
        self,
        seq: u64,
    ) -> Result<StoredCommand<StorableCaCommand>, UpgradeError> {
        let details = Self::storable_ca_command(self.summary)?;

        Ok(StoredCommand::new(
            self.actor,
            self.time,
            self.handle,
            self.version,
            seq,
            details,
            self.effect,
        ))
    }

    fn into_new_stored_pubd_command(
        self,
        seq: u64,
    ) -> Result<StoredCommand<StorableRepositoryCommand>, UpgradeError> {
        let details = Self::storable_pubd_command(self.summary)?;

        Ok(StoredCommand::new(
            self.actor,
            self.time,
            self.handle,
            self.version,
            seq,
            details,
            self.effect,
        ))
    }

    fn storable_ca_command(s: String) -> Result<StorableCaCommand, UpgradeError> {
        if s.starts_with("Turn into Trust Anchor") {
            Ok(StorableCaCommand::MakeTrustAnchor)
        } else if s.starts_with("Add child") {
            PreviousCommand::extract_child_add(&s)
        } else if s.starts_with("Update child") {
            PreviousCommand::extract_child_update(&s)
        } else if s.starts_with("Certify child") {
            PreviousCommand::extract_child_certify(&s)
        } else if s.starts_with("Revoke child") {
            PreviousCommand::extract_child_revoke(&s)
        } else if s.starts_with("Remove child") {
            PreviousCommand::extract_child_remove(&s)
        } else if s.starts_with("Generate a new RFC8183 ID") {
            Ok(StorableCaCommand::GenerateNewIdKey)
        } else if s.starts_with("Add parent") {
            PreviousCommand::extract_add_parent(&s)
        } else if s.starts_with("Update contact for parent") {
            PreviousCommand::extract_update_parent(&s)
        } else if s.starts_with("Remove parent") {
            PreviousCommand::extract_remove_parent(&s)
        } else if s.starts_with("Update entitlements under parent '") {
            PreviousCommand::extract_update_entitlements(&s)
        } else if s.starts_with("Update received cert in RC") {
            PreviousCommand::extract_update_rcvd_cert(&s)
        } else if s.starts_with("Initiate key roll") {
            PreviousCommand::extract_keyroll_init(&s)
        } else if s.starts_with("Activate new keys") {
            PreviousCommand::extract_keyroll_activate(&s)
        } else if s.starts_with("Retire old revoked key") {
            PreviousCommand::extract_keyroll_finish(&s)
        } else if s.starts_with("Update ROAs ") {
            PreviousCommand::extract_update_roas(&s)
        } else if s.starts_with("Republish") {
            Ok(StorableCaCommand::Republish)
        } else if s.starts_with("Update repo to") {
            PreviousCommand::extract_update_repo(&s)
        } else if s.starts_with("Clean up old repository") {
            Ok(StorableCaCommand::RepoRemoveOld)
        } else {
            Err(UpgradeError::unrecognised(s))
        }
    }

    fn storable_pubd_command(s: String) -> Result<StorableRepositoryCommand, UpgradeError> {
        if s.starts_with("Added publisher") {
            PreviousCommand::extract_add_publisher(&s)
        } else if s.starts_with("Remove publisher") {
            PreviousCommand::extract_remove_publisher(&s)
        } else if s.starts_with("Publish for") {
            PreviousCommand::extract_publish_for(&s)
        } else {
            Err(UpgradeError::unrecognised(s))
        }
    }

    fn extract_child_add(s: &str) -> Result<StorableCaCommand, UpgradeError> {
        // Add child 'ca' with RFC8183 key '48bb210a35e6a1f028a3eb907a1db9db1a62c9d4' and resources 'asn: , v4: 10.0.0.0/8, v6: '
        // Note: key = <none> for embedded children.
        let parts = Self::split_string(s, 3)?;
        let child = Self::extract_handle(&parts[0])?;
        let id_ski_opt = if parts[1].as_str() == "<none>" {
            None
        } else {
            Some(parts[1].clone())
        };
        let resources = Self::extract_resource_set(&parts[2])?;
        Ok(StorableCaCommand::ChildAdd(child, id_ski_opt, resources))
    }

    fn extract_child_update(s: &str) -> Result<StorableCaCommand, UpgradeError> {
        // Update child 'child' with new resources: asn: AS1, v4: , v6:
        // Update child 'child' with new id cert
        let lead = "Update child '";
        let with_new = "' with new ";
        let resource_lead = "resources: ";
        let id_cert_txt = "id cert";

        if !s.starts_with(lead) {
            return Err(UpgradeError::unrecognised(s));
        }

        let with_new_start = s
            .find(with_new)
            .ok_or_else(|| UpgradeError::unrecognised(s))?;

        let child = Self::extract_handle(&s[lead.len()..with_new_start])?;

        if let Some(resources_start) = s.find(resource_lead) {
            let res_str = &s[resources_start + resource_lead.len()..];
            let res = Self::extract_resource_set(res_str)?;
            Ok(StorableCaCommand::ChildUpdateResources(child, res))
        } else if s.contains(id_cert_txt) {
            Ok(StorableCaCommand::ChildUpdateId(
                child,
                "<unsaved see events>".to_string(),
            ))
        } else {
            Err(UpgradeError::unrecognised(s))
        }
    }

    fn extract_child_certify(s: &str) -> Result<StorableCaCommand, UpgradeError> {
        // Certify child 'ca' for request 'class name '0' limit 'v4 'all' v6 'all' asn 'all'' csr for key 'B35583F7499241DDEDC3A7F82EB2DFD4672B92D0' rrdp notify 'https://localhost:3000/rrdp/notification.xml' ca repo 'rsync://localhost/repo/ca/0/' mft 'rsync://localhost/repo/ca/0/B35583F7499241DDEDC3A7F82EB2DFD4672B92D0.mft''
        let lead = "Certify child '";
        let lead_rcn = "' for request 'class name '";
        let lead_limit = "' limit '";
        let lead_ki = "' csr for key '";
        let tail_start = "' rrdp notify";

        if !s.starts_with(lead) {
            return Err(UpgradeError::unrecognised(s));
        }

        if s.len()
            < lead.len() + lead_rcn.len() + lead_limit.len() + lead_ki.len() + tail_start.len()
        {
            return Err(UpgradeError::unrecognised(s));
        }

        let lead_rcn_start = s
            .find(lead_rcn)
            .ok_or_else(|| UpgradeError::unrecognised(s))?;

        let lead_limit_start = s
            .find(lead_limit)
            .ok_or_else(|| UpgradeError::unrecognised(s))?;

        let lead_ki_start = s
            .find(lead_ki)
            .ok_or_else(|| UpgradeError::unrecognised(s))?;

        let tail_starts = s
            .find(tail_start)
            .ok_or_else(|| UpgradeError::unrecognised(s))?;

        let child = Self::extract_handle(&s[lead.len()..lead_rcn_start])?;
        let rcn = ResourceClassName::from(&s[lead_rcn_start + lead_rcn.len()..lead_limit_start]);

        let limit_str = &s[lead_limit_start + lead_limit.len()..lead_ki_start];
        let limit = RequestResourceLimit::from_str(limit_str)
            .map_err(|_| UpgradeError::Custom(format!("Cannot parse limit: {}", limit_str)))?;

        let ki_str = &s[lead_ki_start + lead_ki.len()..tail_starts];
        let ki = KeyIdentifier::from_str(ki_str).map_err(|_| {
            UpgradeError::Custom(format!("Cannot parse key identifier: {}", ki_str))
        })?;

        Ok(StorableCaCommand::ChildCertify(child, rcn, limit, ki))
    }

    fn extract_child_revoke(s: &str) -> Result<StorableCaCommand, UpgradeError> {
        // Revoke child 'ca' request 'class name '0' key 'B35583F7499241DDEDC3A7F82EB2DFD4672B92D0''
        let lead = "Revoke child '";
        let lead_rcn = "' request 'class name '";
        let lead_ki = "' key '";

        if !s.starts_with(lead) {
            return Err(UpgradeError::unrecognised(s));
        }

        if s.len() < lead.len() + lead_rcn.len() + lead_ki.len() + 22 {
            return Err(UpgradeError::unrecognised(s));
        }

        let lead_rcn_start = s
            .find(lead_rcn)
            .ok_or_else(|| UpgradeError::unrecognised(s))?;

        let lead_ki_start = s
            .find(lead_ki)
            .ok_or_else(|| UpgradeError::unrecognised(s))?;

        let child = Self::extract_handle(&s[lead.len()..lead_rcn_start])?;
        let rcn = ResourceClassName::from(&s[lead_rcn_start + lead_rcn.len()..lead_ki_start]);

        let ki_str = &s[lead_ki_start + lead_ki.len()..s.len() - 1];
        let ki = KeyIdentifier::from_str(ki_str).map_err(|_| {
            UpgradeError::Custom(format!("Cannot parse key identifier: {}", ki_str))
        })?;

        let revocation_request = RevocationRequest::new(rcn, ki);

        Ok(StorableCaCommand::ChildRevokeKey(child, revocation_request))
    }

    fn extract_child_remove(s: &str) -> Result<StorableCaCommand, UpgradeError> {
        // Remove child 'ca' and revoke&remove its certs
        let parts = Self::split_string(s, 1)?;
        let child = Self::extract_handle(&parts[0])?;
        Ok(StorableCaCommand::ChildRemove(child))
    }

    fn extract_add_parent(s: &str) -> Result<StorableCaCommand, UpgradeError> {
        // Add parent 'ta' as 'RFC 6492 Parent'
        let parts = Self::split_string(s, 2)?;
        let parent = Self::extract_handle(&parts[0])?;
        let contact = match parts[1].as_str() {
            "This CA is a TA" => StorableParentContact::Ta,
            "Embedded parent" => StorableParentContact::Embedded,
            "RFC 6492 Parent" => StorableParentContact::Rfc6492,
            _ => {
                return Err(UpgradeError::Custom(format!(
                    "Unrecognised parent: {}",
                    parts[1]
                )))
            }
        };
        Ok(StorableCaCommand::AddParent(parent, contact))
    }

    fn extract_update_parent(s: &str) -> Result<StorableCaCommand, UpgradeError> {
        // Update contact for parent 'ta' to 'RFC 6492 Parent'
        let parts = Self::split_string(s, 2)?;
        let parent = Self::extract_handle(&parts[0])?;
        let contact = match parts[1].as_str() {
            "This CA is a TA" => StorableParentContact::Ta,
            "Embedded parent" => StorableParentContact::Embedded,
            "RFC 6492 Parent" => StorableParentContact::Rfc6492,
            _ => {
                return Err(UpgradeError::Custom(format!(
                    "Unrecognised parent: {}",
                    parts[1]
                )))
            }
        };
        Ok(StorableCaCommand::UpdateParentContact(parent, contact))
    }

    fn extract_remove_parent(s: &str) -> Result<StorableCaCommand, UpgradeError> {
        // Remove parent 'ta'
        let parts = Self::split_string(s, 1)?;
        let parent = Self::extract_handle(&parts[0])?;
        Ok(StorableCaCommand::RemoveParent(parent))
    }

    fn extract_update_repo(s: &str) -> Result<StorableCaCommand, UpgradeError> {
        // Update repo to embedded server
        // Update repo to server at: https://localhost:3000/rfc8181/ca
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() == 1 {
            Ok(StorableCaCommand::RepoUpdate(None))
        } else {
            let uri = parts[1].trim();
            let service_uri = ServiceUri::try_from(uri.to_string()).map_err(|e| {
                UpgradeError::Custom(format!(
                    "Cannot parse service uri: {}, Error: {}",
                    parts[1],
                    e.to_string()
                ))
            })?;
            Ok(StorableCaCommand::RepoUpdate(Some(service_uri)))
        }
    }

    fn extract_update_entitlements(s: &str) -> Result<StorableCaCommand, UpgradeError> {
        // Update entitlements under parent 'ta' to 'class name '0' issuing key 'D2FB29F9A9F58E481BC502BFB40FF2CE0EA76A41' resources 'asn: , v4: 10.0.0.0/16, v6: ' issued ''
        if s.len() < 41 {
            return Err(UpgradeError::unrecognised(s));
        }

        let start_quote_to = s
            .find("' to '")
            .ok_or_else(|| UpgradeError::unrecognised(s))?;
        let parent = Self::extract_handle(&s[34..start_quote_to])?;
        let update_str = &s[start_quote_to + 6..s.len()];

        let mut classes = BTreeMap::new();
        if !update_str.starts_with("class name ") {
            return Err(UpgradeError::unrecognised(s));
        }
        let update_str = &update_str[11..];

        let class_update_strings: Vec<&str> = update_str.split("class name ").collect();
        for class_update_str in class_update_strings {
            let parts = Self::split_string(class_update_str, 4)?;
            let class_name = ResourceClassName::from(parts[0].as_str());
            let resources = ResourceSet::from_str(&parts[2]).map_err(|e| {
                UpgradeError::Custom(format!(
                    "Cannot parse resources in update entitlements: {}",
                    e
                ))
            })?;
            classes.insert(class_name, resources);
        }

        Ok(StorableCaCommand::UpdateResourceClasses(parent, classes))
    }

    fn extract_update_rcvd_cert(s: &str) -> Result<StorableCaCommand, UpgradeError> {
        // Update received cert in RC '0', with resources 'asn: AS0-AS4294967295, v4: 0.0.0.0/0, v6: ::/0'
        let parts = Self::split_string(s, 2)?;
        let rcn = ResourceClassName::from(parts[0].as_str());
        let resources = ResourceSet::from_str(parts[1].as_str()).map_err(UpgradeError::custom)?;

        Ok(StorableCaCommand::UpdateRcvdCert(rcn, resources))
    }

    fn extract_keyroll_init(s: &str) -> Result<StorableCaCommand, UpgradeError> {
        // Initiate key roll for keys older than '60'
        let parts = Self::split_string(s, 1)?;
        let seconds = Self::extract_seconds(&parts[0])?;
        Ok(StorableCaCommand::KeyRollInitiate(seconds))
    }

    fn extract_keyroll_activate(s: &str) -> Result<StorableCaCommand, UpgradeError> {
        // Activate new keys older than '{}' in key roll
        let parts = Self::split_string(s, 1)?;
        let seconds = Self::extract_seconds(&parts[0])?;
        Ok(StorableCaCommand::KeyRollActivate(seconds))
    }

    fn extract_seconds(s: &str) -> Result<i64, UpgradeError> {
        // Format is: PxxDTyyS or PTyyS if < 1 day
        let mut seconds = 0;
        if !s.starts_with('P') {
            return Err(UpgradeError::Custom(format!("Invalid period: {}", s)));
        }

        if let Some(d_ix) = s.find('D') {
            let days = &s[1..d_ix];
            let days = Self::extract_i64(days)?;
            seconds += 86400 * days;
        }

        let s_ix = s.find('T').ok_or_else(|| UpgradeError::unrecognised(s))?;
        let sec_str = &s[s_ix + 1..s.len() - 1];
        seconds += Self::extract_i64(sec_str)?;

        Ok(seconds)
    }

    fn extract_i64(s: &str) -> Result<i64, UpgradeError> {
        i64::from_str(s).map_err(UpgradeError::custom)
    }

    fn extract_keyroll_finish(s: &str) -> Result<StorableCaCommand, UpgradeError> {
        // Retire old revoked key in RC '0'
        let parts = Self::split_string(s, 1)?;
        let rcn = ResourceClassName::from(parts[0].as_str());
        Ok(StorableCaCommand::KeyRollFinish(rcn))
    }

    fn extract_update_roas(s: &str) -> Result<StorableCaCommand, UpgradeError> {
        // Update ROAs 'added: 2a04:b900::/29 => 199664 2a04:b900::/29 => 8587 185.49.140.0/22 => 8587 185.49.140.0/22 => 199664 '
        let parts = Self::split_string(s, 1)?;
        let update_str = parts[0].as_str();

        let mut added = HashSet::new();
        let mut removed = HashSet::new();

        if update_str.starts_with("added: ") {
            let end = update_str
                .find("removed: ")
                .unwrap_or_else(|| update_str.len());
            let added_str = &update_str[7..end];

            Self::extract_roas(added_str, &mut added).map_err(|e| {
                UpgradeError::Custom(format!(
                    "Could not parse added ROAs in summary: {}, Error: {}",
                    s, e
                ))
            })?;
        }

        if let Some(start) = update_str.find("removed: ") {
            let removed_str = &update_str[start + 9..];
            Self::extract_roas(removed_str, &mut removed).map_err(|e| {
                UpgradeError::Custom(format!(
                    "Could not parse removed ROAs in summary: {}, Error: {}",
                    s, e
                ))
            })?;
        }

        Ok(StorableCaCommand::RoaDefinitionUpdates(
            RoaDefinitionUpdates::new(added, removed),
        ))
    }

    fn extract_roas(s: &str, set: &mut HashSet<RoaDefinition>) -> Result<(), UpgradeError> {
        // 2a04:b900::/29 => 199664 2a04:b900::/29 => 8587 185.49.140.0/22 => 8587 185.49.140.0/22 => 199664
        let mut remaining = s.trim();

        while !remaining.is_empty() {
            let sep_start = remaining.find(" => ").ok_or_else(|| {
                UpgradeError::Custom(format!("Invalid ROA string: {}", remaining))
            })?;

            let prefix = &remaining[0..sep_start];

            remaining = &remaining[sep_start + 4..];
            let end = remaining.find(' ').unwrap_or_else(|| remaining.len());

            let asn = &remaining[0..end];

            let roa = format!("{} => {}", prefix, asn);
            let roa = RoaDefinition::from_str(roa.as_str()).map_err(UpgradeError::custom)?;

            set.insert(roa);

            remaining = &remaining[end..];
        }

        Ok(())
    }

    fn extract_add_publisher(s: &str) -> Result<StorableRepositoryCommand, UpgradeError> {
        // Added publisher '{}' with id cert hash '{}'
        let parts = Self::split_string(s, 2)?;
        let publisher = Self::extract_handle(&parts[0])?;
        let ski = &parts[1];
        Ok(StorableRepositoryCommand::AddPublisher(
            publisher,
            ski.clone(),
        ))
    }

    fn extract_remove_publisher(s: &str) -> Result<StorableRepositoryCommand, UpgradeError> {
        // Remove publisher '{}' and all its objects
        let parts = Self::split_string(s, 1)?;
        let publisher = Self::extract_handle(&parts[0])?;
        Ok(StorableRepositoryCommand::RemovePublisher(publisher))
    }

    fn extract_publish_for(s: &str) -> Result<StorableRepositoryCommand, UpgradeError> {
        // Publish for '{}': {} new, {} updated, {} withdrawn objects
        let lead = "Publish for '";
        let lead_published = "': ";
        let lead_updated = " new, ";
        let lead_withdrawn = " updated, ";
        let tail = " withdrawn objects";

        if !s.starts_with(lead) {
            return Err(UpgradeError::unrecognised(s));
        }

        let lead_published_start = s
            .find(lead_published)
            .ok_or_else(|| UpgradeError::unrecognised(s))?;
        let lead_updated_start = s
            .find(lead_updated)
            .ok_or_else(|| UpgradeError::unrecognised(s))?;
        let lead_withdrawn_start = s
            .find(lead_withdrawn)
            .ok_or_else(|| UpgradeError::unrecognised(s))?;
        let tail_start = s.find(tail).ok_or_else(|| UpgradeError::unrecognised(s))?;

        let publisher = Self::extract_handle(&s[lead.len()..lead_published_start])?;

        let published_str = &s[lead_published_start + lead_published.len()..lead_updated_start];
        let updated_str = &s[lead_updated_start + lead_updated.len()..lead_withdrawn_start];
        let withdrawn_str = &s[lead_withdrawn_start + lead_withdrawn.len()..tail_start];

        let published = Self::extract_i64(published_str)? as usize;
        let updated = Self::extract_i64(updated_str)? as usize;
        let withdrawn = Self::extract_i64(withdrawn_str)? as usize;

        Ok(StorableRepositoryCommand::Publish(
            publisher, published, updated, withdrawn,
        ))
    }

    fn extract_handle(s: &str) -> Result<Handle, UpgradeError> {
        Handle::from_str(s).map_err(|_| UpgradeError::Custom(format!("invalid handle: {}", s)))
    }

    fn extract_resource_set(s: &str) -> Result<ResourceSet, UpgradeError> {
        ResourceSet::from_str(s).map_err(|e| {
            UpgradeError::Custom(format!("Cannot parse resources: {}, Error: {}", s, e))
        })
    }

    /// Extract the quoted strings in the command string. Wants to know how many quoted
    /// things to expect. Returns and error if it finds the wrong number.
    fn split_string(s: &str, expected: usize) -> Result<Vec<String>, UpgradeError> {
        let parts: Vec<&str> = s.split('\'').collect();

        let expected_parts_nr = expected * 2;
        if parts.len() != expected_parts_nr && parts.len() != (expected_parts_nr + 1) {
            Err(UpgradeError::Custom(format!(
                "Expected '{}' quoted values in string: {}",
                expected, s
            )))
        } else {
            let mut res = vec![];
            for i in 1..=expected {
                res.push(parts[i * 2 - 1].to_string())
            }

            Ok(res)
        }
    }
}
