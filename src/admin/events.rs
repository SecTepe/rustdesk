// Broadcast channel that feeds the `/admin/api/events` SSE stream.
//
// Whenever a support request or device record changes, handlers publish a
// `AdminEvent` here. Connected browsers receive them over Server-Sent Events
// and update the dashboard live without polling.

use std::sync::OnceLock;

use hbb_common::tokio::sync::broadcast;
use serde::Serialize;

use crate::admin::model::{RegisteredDevice, SupportRequest};

/// Shape of a single SSE event.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum AdminEvent {
    RequestCreated(SupportRequest),
    RequestUpdated(SupportRequest),
    DeviceUpserted(RegisteredDevice),
    DeviceRemoved { id: String },
}

fn channel() -> &'static broadcast::Sender<AdminEvent> {
    static CHAN: OnceLock<broadcast::Sender<AdminEvent>> = OnceLock::new();
    CHAN.get_or_init(|| broadcast::channel::<AdminEvent>(64).0)
}

/// Publish an event. Failures (no receivers) are intentionally silent — the
/// admin dashboard is best-effort live; clients resync on reconnect.
pub fn publish(event: AdminEvent) {
    let _ = channel().send(event);
}

/// Subscribe to the global event stream. Used by the SSE handler.
pub fn subscribe() -> broadcast::Receiver<AdminEvent> {
    channel().subscribe()
}
