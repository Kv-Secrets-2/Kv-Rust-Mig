use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use serde_json::{Number, Value};

use crate::approvals::{MAX_STORED_APPROVAL_REQUESTS, epoch, request_content_digest};
use crate::{Result, invalid};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestRecord {
    pub request_id: String,
    pub content_digest: String,
    pub environment: String,
    pub network: bool,
    pub network_reason: String,
    pub expires_at_epoch: Number,
}

#[derive(Debug, thiserror::Error)]
#[error(
    "the daemon's request records are full ({bound}); let pending requests expire or decide them, then try again"
)]
pub struct RequestRecordsFull {
    pub bound: usize,
}

pub fn record_of(request: &Value) -> Result<RequestRecord> {
    if !request.is_object() {
        return Err(invalid("a request must be an object"));
    }
    let text = |key: &str| request[key].as_str().filter(|s| !s.is_empty());
    let expires = request["expires_at_epoch"]
        .as_number()
        .filter(|n| !n.to_string().contains(['.', 'e', 'E']));
    let (Some(id), Some(environment), Some(network), Some(reason), Some(expires)) = (
        text("request_id"),
        text("environment"),
        request["network"].as_bool(),
        text("network_reason"),
        expires,
    ) else {
        return Err(invalid(
            "a recorded request needs its id, environment, network, network_reason and expiry",
        ));
    };
    Ok(RequestRecord {
        request_id: id.into(),
        content_digest: request_content_digest(request)?,
        environment: environment.into(),
        network,
        network_reason: reason.into(),
        expires_at_epoch: expires.clone(),
    })
}

pub struct RequestRecords {
    bound: usize,
    records: Mutex<HashMap<String, RequestRecord>>,
}

impl Default for RequestRecords {
    fn default() -> Self {
        Self::new(None)
    }
}

impl RequestRecords {
    pub fn new(bound: Option<usize>) -> Self {
        Self {
            bound: bound.unwrap_or(MAX_STORED_APPROVAL_REQUESTS),
            records: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, HashMap<String, RequestRecord>>> {
        self.records
            .lock()
            .map_err(|_| invalid("request records lock is poisoned"))
    }

    pub fn record(&self, request: &Value, now: Option<i64>) -> Result<RequestRecord> {
        let candidate = record_of(request)?;
        let now = epoch(now);
        let mut records = self.lock()?;
        prune(&mut records, now);
        if let Some(existing) = records.get(&candidate.request_id) {
            return Ok(existing.clone());
        }
        if records.len() >= self.bound {
            return Err(RequestRecordsFull { bound: self.bound }.into());
        }
        records.insert(candidate.request_id.clone(), candidate.clone());
        Ok(candidate)
    }

    pub fn get(&self, request_id: &str, now: Option<i64>) -> Result<Option<RequestRecord>> {
        let now = epoch(now);
        let mut records = self.lock()?;
        prune(&mut records, now);
        Ok(records.get(request_id).cloned())
    }

    pub fn len(&self) -> Result<usize> {
        Ok(self.lock()?.len())
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

fn prune(records: &mut HashMap<String, RequestRecord>, now: i64) {
    records.retain(|_, record| {
        let expiry = record.expires_at_epoch.to_string();
        expiry
            .parse::<i64>()
            .map_or_else(|_| !expiry.starts_with('-'), |expiry| expiry > now)
    });
}
