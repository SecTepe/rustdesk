// JSON-backed, single-file store for the admin console.
//
// The store holds a `Vec<RegisteredDevice>` and a `Vec<SupportRequest>` and is
// persisted to `<config_dir>/admin_store.json`. Writes use the familiar
// atomic-rename pattern: serialize → write to `<path>.tmp` → `rename`. A
// process-global `Mutex` guards concurrent writers from a single process.
//
// Deliberately simple: no SQL, no indexing. The expected working set is small
// (dozens to low hundreds of devices, queue of pending requests). If that ever
// grows, swap the store behind the same API.

use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};

use hbb_common::{config::Config, log, ResultType};
use serde::{Deserialize, Serialize};

use crate::admin::model::{RegisteredDevice, RequestStatus, SupportRequest};

/// On-disk format. Keep this struct backwards compatible — add new fields with
/// `#[serde(default)]`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AdminStoreData {
    #[serde(default)]
    pub devices: Vec<RegisteredDevice>,
    #[serde(default)]
    pub requests: Vec<SupportRequest>,
}

pub struct AdminStore {
    path: PathBuf,
    data: Mutex<AdminStoreData>,
}

impl AdminStore {
    /// Open (or lazily create) the store at the default location under the
    /// rustdesk config directory.
    pub fn open_default() -> ResultType<Self> {
        let path = default_store_path();
        Self::open_at(path)
    }

    /// Open (or create) a store at an arbitrary path. Used by tests.
    pub fn open_at<P: AsRef<Path>>(path: P) -> ResultType<Self> {
        let path = path.as_ref().to_path_buf();
        let data = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            if raw.trim().is_empty() {
                AdminStoreData::default()
            } else {
                serde_json::from_str::<AdminStoreData>(&raw).unwrap_or_else(|e| {
                    log::warn!(
                        "admin_store: failed to parse existing file ({}), starting fresh",
                        e
                    );
                    AdminStoreData::default()
                })
            }
        } else {
            AdminStoreData::default()
        };
        Ok(Self {
            path,
            data: Mutex::new(data),
        })
    }

    fn persist(&self, data: &AdminStoreData) -> ResultType<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let pretty = serde_json::to_string_pretty(data)?;
        std::fs::write(&tmp, pretty)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    // ---------------- devices ----------------

    pub fn list_devices(&self) -> Vec<RegisteredDevice> {
        self.data.lock().unwrap().devices.clone()
    }

    pub fn get_device(&self, id: &str) -> Option<RegisteredDevice> {
        self.data
            .lock()
            .unwrap()
            .devices
            .iter()
            .find(|d| d.id == id)
            .cloned()
    }

    /// Insert or update a device keyed by `id`. Returns the stored record.
    pub fn upsert_device(&self, mut device: RegisteredDevice) -> ResultType<RegisteredDevice> {
        let mut data = self.data.lock().unwrap();
        if let Some(existing) = data.devices.iter_mut().find(|d| d.id == device.id) {
            // Preserve admin-assigned metadata across re-enroll.
            if device.alias.is_empty() {
                device.alias = existing.alias.clone();
            }
            if device.owner_email.is_none() {
                device.owner_email = existing.owner_email.clone();
            }
            if device.tags.is_empty() {
                device.tags = existing.tags.clone();
            }
            if device.note.is_empty() {
                device.note = existing.note.clone();
            }
            if device.enrolled_at == 0 {
                device.enrolled_at = existing.enrolled_at;
            }
            *existing = device.clone();
        } else {
            data.devices.push(device.clone());
        }
        self.persist(&data)?;
        Ok(device)
    }

    /// Apply an admin-driven partial update. Unknown ids return an error.
    pub fn patch_device(&self, id: &str, patch: DevicePatch) -> ResultType<RegisteredDevice> {
        let mut data = self.data.lock().unwrap();
        let dev = data
            .devices
            .iter_mut()
            .find(|d| d.id == id)
            .ok_or_else(|| hbb_common::anyhow::anyhow!("device not found"))?;
        if let Some(v) = patch.alias {
            dev.alias = v;
        }
        if let Some(v) = patch.owner_email {
            dev.owner_email = Some(v);
        }
        if let Some(v) = patch.tags {
            dev.tags = v;
        }
        if let Some(v) = patch.note {
            dev.note = v;
        }
        let snap = dev.clone();
        self.persist(&data)?;
        Ok(snap)
    }

    pub fn delete_device(&self, id: &str) -> ResultType<bool> {
        let mut data = self.data.lock().unwrap();
        let before = data.devices.len();
        data.devices.retain(|d| d.id != id);
        let removed = data.devices.len() != before;
        if removed {
            self.persist(&data)?;
        }
        Ok(removed)
    }

    /// Update the `last_seen` column for an existing device. Silent no-op if
    /// the device is not yet registered.
    pub fn touch_device(&self, id: &str, now: i64) -> ResultType<()> {
        let mut data = self.data.lock().unwrap();
        if let Some(dev) = data.devices.iter_mut().find(|d| d.id == id) {
            dev.last_seen = Some(now);
            self.persist(&data)?;
        }
        Ok(())
    }

    // ---------------- requests ----------------

    pub fn list_requests(&self, status_filter: Option<RequestStatus>) -> Vec<SupportRequest> {
        let data = self.data.lock().unwrap();
        data.requests
            .iter()
            .filter(|r| status_filter.map_or(true, |s| r.status == s))
            .cloned()
            .collect()
    }

    pub fn get_request(&self, id: &str) -> Option<SupportRequest> {
        self.data
            .lock()
            .unwrap()
            .requests
            .iter()
            .find(|r| r.id == id)
            .cloned()
    }

    pub fn push_request(&self, req: SupportRequest) -> ResultType<SupportRequest> {
        let mut data = self.data.lock().unwrap();
        data.requests.push(req.clone());
        self.persist(&data)?;
        Ok(req)
    }

    pub fn update_request_status(
        &self,
        id: &str,
        status: RequestStatus,
        admin: Option<String>,
        reject_reason: Option<String>,
        now: i64,
    ) -> ResultType<SupportRequest> {
        let mut data = self.data.lock().unwrap();
        let req = data
            .requests
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| hbb_common::anyhow::anyhow!("request not found"))?;
        req.status = status;
        req.handled_at = Some(now);
        if admin.is_some() {
            req.approved_by = admin;
        }
        if reject_reason.is_some() {
            req.reject_reason = reject_reason;
        }
        let snap = req.clone();
        self.persist(&data)?;
        Ok(snap)
    }
}

/// Partial update payload for `PATCH /admin/api/devices/:id`.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct DevicePatch {
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub owner_email: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub note: Option<String>,
}

fn default_store_path() -> PathBuf {
    Config::path("admin_store.json")
}

/// Convenience: return the current unix seconds. Centralised so tests can
/// swap it out via injection.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::model::RequestStatus;

    fn tmp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "rustdesk_admin_store_test_{}_{}.json",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn device_roundtrip() {
        let path = tmp_path("devices");
        let store = AdminStore::open_at(&path).unwrap();
        let dev = RegisteredDevice::new_enrolled(
            "123456789".into(),
            "uuid".into(),
            "host".into(),
            "linux".into(),
            1000,
        );
        store.upsert_device(dev.clone()).unwrap();
        let listed = store.list_devices();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "123456789");

        // Reopen and confirm the file round-trips.
        drop(store);
        let store2 = AdminStore::open_at(&path).unwrap();
        assert_eq!(store2.list_devices().len(), 1);

        store2
            .patch_device(
                "123456789",
                DevicePatch {
                    alias: Some("lab-pc".into()),
                    tags: Some(vec!["lab".into(), "linux".into()]),
                    ..Default::default()
                },
            )
            .unwrap();
        let patched = store2.get_device("123456789").unwrap();
        assert_eq!(patched.alias, "lab-pc");
        assert_eq!(patched.tags, vec!["lab", "linux"]);

        assert!(store2.delete_device("123456789").unwrap());
        assert!(store2.list_devices().is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn request_lifecycle() {
        let path = tmp_path("requests");
        let store = AdminStore::open_at(&path).unwrap();
        let req = SupportRequest {
            id: "abc".into(),
            device_id: "987654321".into(),
            device_uuid: "".into(),
            requester_name: "alice".into(),
            reason: "printer broken".into(),
            created_at: 100,
            status: RequestStatus::Pending,
            approved_by: None,
            handled_at: None,
            connection_log_id: None,
            reject_reason: None,
        };
        store.push_request(req.clone()).unwrap();

        let pending = store.list_requests(Some(RequestStatus::Pending));
        assert_eq!(pending.len(), 1);

        store
            .update_request_status(
                "abc",
                RequestStatus::Approved,
                Some("admin@example".into()),
                None,
                200,
            )
            .unwrap();
        let approved = store.get_request("abc").unwrap();
        assert_eq!(approved.status, RequestStatus::Approved);
        assert_eq!(approved.approved_by.as_deref(), Some("admin@example"));
        assert_eq!(approved.handled_at, Some(200));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn upsert_preserves_admin_metadata() {
        let path = tmp_path("upsert");
        let store = AdminStore::open_at(&path).unwrap();

        let mut dev = RegisteredDevice::new_enrolled(
            "1".into(),
            "u".into(),
            "h1".into(),
            "linux".into(),
            100,
        );
        dev.alias = "".into();
        store.upsert_device(dev).unwrap();

        // Admin sets an alias.
        store
            .patch_device(
                "1",
                DevicePatch {
                    alias: Some("kiosk".into()),
                    ..Default::default()
                },
            )
            .unwrap();

        // Device re-enrolls with a refreshed hostname but no alias.
        let reenroll = RegisteredDevice::new_enrolled(
            "1".into(),
            "u".into(),
            "h2".into(),
            "linux".into(),
            200,
        );
        store.upsert_device(reenroll).unwrap();

        let got = store.get_device("1").unwrap();
        assert_eq!(got.alias, "kiosk");
        assert_eq!(got.hostname, "h2");
        let _ = std::fs::remove_file(&path);
    }
}

