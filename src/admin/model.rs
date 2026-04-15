// Data model for the admin web console.
//
// Two top-level entities:
//   * `RegisteredDevice` — a device known to the admin fleet. Populated by
//     self-enroll on first heartbeat or by explicit admin action.
//   * `SupportRequest`   — a pending / historical support session request
//     created by an end user clicking "Request Support" in the Flutter UI.

use serde::{Deserialize, Serialize};

/// A device known to the admin fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredDevice {
    /// RustDesk peer id (e.g. 9 digits).
    pub id: String,
    /// Installation uuid (base64 of `hbb_common::get_uuid()`).
    #[serde(default)]
    pub uuid: String,
    /// Admin-assigned friendly name.
    #[serde(default)]
    pub alias: String,
    /// OS hostname reported by the device.
    #[serde(default)]
    pub hostname: String,
    /// Lowercase OS family: "windows" / "linux" / "macos" / "android" / "ios".
    #[serde(default)]
    pub os: String,
    /// Optional owner contact. Purely informational.
    #[serde(default)]
    pub owner_email: Option<String>,
    /// Free-form tags used for filtering in the admin UI.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Free-form admin note.
    #[serde(default)]
    pub note: String,
    /// Unix seconds when the device was first enrolled.
    pub enrolled_at: i64,
    /// Unix seconds of the most recent heartbeat or admin edit.
    #[serde(default)]
    pub last_seen: Option<i64>,
}

impl RegisteredDevice {
    /// Build a new device record from an auto-enroll payload. `now` is injected
    /// so tests can produce deterministic values.
    pub fn new_enrolled(id: String, uuid: String, hostname: String, os: String, now: i64) -> Self {
        Self {
            id,
            uuid,
            alias: String::new(),
            hostname,
            os,
            owner_email: None,
            tags: Vec::new(),
            note: String::new(),
            enrolled_at: now,
            last_seen: Some(now),
        }
    }
}

/// Lifecycle states for a `SupportRequest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestStatus {
    Pending,
    Approved,
    Rejected,
    Connected,
    Closed,
}

impl RequestStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RequestStatus::Pending => "pending",
            RequestStatus::Approved => "approved",
            RequestStatus::Rejected => "rejected",
            RequestStatus::Connected => "connected",
            RequestStatus::Closed => "closed",
        }
    }
}

/// A single support request. Created by end-user clients, consumed by the
/// admin dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportRequest {
    /// UUIDv4 generated on the server when the request is accepted.
    pub id: String,
    /// RustDesk id of the requesting device.
    pub device_id: String,
    /// Installation uuid of the requesting device.
    #[serde(default)]
    pub device_uuid: String,
    /// Best-effort "who is asking" — typically the OS username.
    #[serde(default)]
    pub requester_name: String,
    /// Free text the end user entered in the request dialog.
    #[serde(default)]
    pub reason: String,
    /// Unix seconds of creation.
    pub created_at: i64,
    /// Current status.
    pub status: RequestStatus,
    /// Email / display name of the admin that handled the request.
    #[serde(default)]
    pub approved_by: Option<String>,
    /// Unix seconds of last status change.
    #[serde(default)]
    pub handled_at: Option<i64>,
    /// Optional link to the active `Connection::alive_conns` id of the
    /// technician session, once established.
    #[serde(default)]
    pub connection_log_id: Option<i32>,
    /// Reason set by the admin when rejecting a request.
    #[serde(default)]
    pub reject_reason: Option<String>,
}

/// Payload accepted by the public `/admin/api/public/requests` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSupportRequest {
    pub device_id: String,
    #[serde(default)]
    pub device_uuid: String,
    #[serde(default)]
    pub requester_name: String,
    #[serde(default)]
    pub reason: String,
    /// Unix seconds of the client clock, used for HMAC binding.
    pub timestamp: i64,
    /// Hex-encoded HMAC-SHA256 of `device_id|device_uuid|timestamp` using the
    /// shared enrollment secret.
    pub signature: String,
}

/// Payload accepted by `/admin/api/public/enroll`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollPayload {
    pub id: String,
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub os: String,
    pub timestamp: i64,
    pub signature: String,
}
