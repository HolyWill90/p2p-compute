//! Persistent bond ledger: per-worker balances across jobs, with a
//! history of decisions. The scaffold's stand-in for on-chain escrow.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ledger {
    pub balances: BTreeMap<String, i64>,
    pub history: Vec<LedgerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub job_id: String,
    pub decision: String,
    pub deltas: Vec<(String, i64)>,
}

impl Ledger {
    /// A missing file is an empty ledger; a corrupt one is an error —
    /// silently resetting balances would be theft.
    pub fn load(path: &Path) -> Result<Ledger, String> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("ledger: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Ledger::default()),
            Err(e) => Err(format!("ledger: {e}")),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| format!("ledger: {e}"))?;
        std::fs::write(path, json).map_err(|e| format!("ledger: {e}"))
    }

    pub fn apply(&mut self, job_id: &str, decision: &str, deltas: &[(String, i64)]) {
        for (id, delta) in deltas {
            *self.balances.entry(id.clone()).or_insert(0) += delta;
        }
        self.history.push(LedgerEntry {
            job_id: job_id.to_string(),
            decision: decision.to_string(),
            deltas: deltas.to_vec(),
        });
    }
}
