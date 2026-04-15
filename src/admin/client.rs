// End-user side of the admin console integration.
//
// Provides two fire-and-forget functions that the non-admin rustdesk client
// uses:
//
//   * `create_support_request(reason)` — posts a new support request to the
//     configured admin server. Invoked from the Flutter "Request Support"
//     button via FFI.
//   * `enroll_self()`                  — signs the current device into the
//     admin fleet. Called once from the heartbeat loop on first successful
//     heartbeat.
//
// Both functions rely on two `Config` options:
//
//   * `admin-server-url`    — e.g. `https://admin.internal:21119`. Empty ⇒
//     feature is disabled, calls are no-ops that return an error.
//   * `admin-enroll-secret` — shared HMAC secret so the public endpoints can
//     tell legitimate devices from random internet noise.
//
// The posts go through `crate::post_request` so TLS, TCP-proxy, and retries
// are inherited from the existing http stack.

use std::sync::Mutex;

use hbb_common::{
    config::{Config, LocalConfig},
    log, ResultType,
};

use crate::admin::auth::sign_message;
use crate::admin::model::{EnrollPayload, NewSupportRequest};
use crate::admin::store::now_secs;

/// Latest status string shown to the end user in the "Request Support"
/// dialog. Polled over FFI from Dart.
static LAST_STATUS: Mutex<String> = Mutex::new(String::new());

pub fn last_status() -> String {
    LAST_STATUS.lock().unwrap().clone()
}

fn set_status(s: impl Into<String>) {
    *LAST_STATUS.lock().unwrap() = s.into();
}

fn admin_server_url() -> Option<String> {
    let url = Config::get_option("admin-server-url");
    if url.is_empty() {
        None
    } else {
        Some(url.trim_end_matches('/').to_owned())
    }
}

fn enrollment_secret() -> Option<String> {
    let s = Config::get_option("admin-enroll-secret");
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Has the admin configured a working server URL for this device? Used to
/// gate the "Request Support" button in the UI.
pub fn is_enabled() -> bool {
    admin_server_url().is_some() && enrollment_secret().is_some()
}

/// Build and send a new support request to the configured admin server.
///
/// Returns `Ok(())` on an HTTP 2xx, otherwise propagates the error. Always
/// updates `LAST_STATUS` so the Flutter dialog can display progress.
pub async fn create_support_request(reason: String) -> ResultType<()> {
    let url = admin_server_url()
        .ok_or_else(|| hbb_common::anyhow::anyhow!("admin-server-url not configured"))?;
    let secret = enrollment_secret()
        .ok_or_else(|| hbb_common::anyhow::anyhow!("admin-enroll-secret not configured"))?;
    let device_id = Config::get_id();
    let device_uuid = crate::encode64(hbb_common::get_uuid());
    let timestamp = now_secs();
    let message = format!("{}|{}|{}", device_id, device_uuid, timestamp);
    let signature = sign_message(&secret, &message);

    let payload = NewSupportRequest {
        device_id: device_id.clone(),
        device_uuid: device_uuid.clone(),
        requester_name: LocalConfig::get_option("custom-device-name"),
        reason,
        timestamp,
        signature,
    };
    let body = serde_json::to_string(&payload)?;
    let full_url = format!("{}/admin/api/public/requests", url);

    set_status("Sending support request...");
    match crate::post_request(full_url, body, "").await {
        Ok(resp) => {
            log::info!("admin: support request sent, response len = {}", resp.len());
            set_status("Support request sent. Waiting for an admin to respond.");
            Ok(())
        }
        Err(err) => {
            log::error!("admin: support request failed: {}", err);
            set_status(format!("Failed to send support request: {}", err));
            Err(err)
        }
    }
}

/// Synchronous wrapper for the FFI layer, which is not async. Spawns onto the
/// current tokio runtime.
pub fn create_support_request_blocking(reason: String) -> bool {
    set_status("Preparing support request...");
    let handle = std::thread::spawn(move || {
        let rt = match hbb_common::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(err) => {
                set_status(format!("Runtime error: {}", err));
                return false;
            }
        };
        rt.block_on(async move { create_support_request(reason).await.is_ok() })
    });
    handle.join().unwrap_or(false)
}

/// Self-enroll the current device with the admin server. Best-effort.
pub async fn enroll_self() -> ResultType<()> {
    let url = admin_server_url()
        .ok_or_else(|| hbb_common::anyhow::anyhow!("admin-server-url not configured"))?;
    let secret = enrollment_secret()
        .ok_or_else(|| hbb_common::anyhow::anyhow!("admin-enroll-secret not configured"))?;
    let id = Config::get_id();
    let uuid = crate::encode64(hbb_common::get_uuid());
    let sysinfo = crate::get_sysinfo();
    let hostname = sysinfo["hostname"].as_str().unwrap_or("").to_owned();
    let os = sysinfo["os"].as_str().unwrap_or("").to_lowercase();
    let timestamp = now_secs();
    let message = format!("{}|{}|{}", id, uuid, timestamp);
    let signature = sign_message(&secret, &message);

    let payload = EnrollPayload {
        id,
        uuid,
        hostname,
        os,
        timestamp,
        signature,
    };
    let body = serde_json::to_string(&payload)?;
    let full_url = format!("{}/admin/api/public/enroll", url);
    let _ = crate::post_request(full_url, body, "").await?;
    Ok(())
}
