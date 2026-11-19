use super::{Manager, bad, gateway::identity, journal::Removal, runtime, storage};
use serde_json::json;
use std::io;

impl Manager {
    pub(super) async fn remove(&mut self, id: &str) -> io::Result<()> {
        let mut slot = self.journal.slot(id)?.clone();
        match slot.removal {
            Removal::Removed | Removal::Purged => return Ok(()),
            Removal::Purging => return Err(bad("Data purge is in progress")),
            Removal::Installed | Removal::Removing => (),
        }
        if slot.provider_dependencies_unknown {
            return Err(bad(
                "Installed provider dependencies require explicit resolution",
            ));
        }
        if slot.generation > 0 {
            self.gateway
                .post("removable", json!({"identity": identity(id,&slot)}))
                .await?;
        }
        slot.removal = Removal::Removing;
        slot.desired_running = false;
        self.journal.save(id, slot)?;
        let _writer = self.fence(id).await?;
        let mut slot = self.journal.slot(id)?.clone();
        if slot.generation > 0 {
            self.gateway
                .post("removable", json!({"identity":identity(id,&slot)}))
                .await?;
        }
        slot.active = None;
        slot.candidate = None;
        slot.previous = None;
        slot.recovery_required = false;
        slot.removal = Removal::Removed;
        self.journal.save(id, slot)
    }

    pub(super) async fn purge(&mut self, id: &str) -> io::Result<()> {
        let mut slot = self.journal.slot(id)?.clone();
        match slot.removal {
            Removal::Purged => return Ok(()),
            Removal::Removed | Removal::Purging => (),
            _ => return Err(bad("Data purge requires a completed removal")),
        }
        let _writer = self.writer(slot.uid).await?;
        slot.removal = Removal::Purging;
        self.journal.save(id, slot.clone())?;
        if slot.generation > 0 {
            self.gateway
                .post("purge-data", json!({"identity":identity(id,&slot)}))
                .await?;
            if slot.database_provisioned {
                runtime::purge_database(slot.uid).await?;
            }
            storage::purge(id, &slot)?;
        }
        slot.written = None;
        slot.database_provisioned = false;
        slot.recovery_required = false;
        slot.removal = Removal::Purged;
        self.journal.save(id, slot)
    }
}
