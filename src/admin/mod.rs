// Admin web console module.
//
// This module ships an embedded HTTP server + single-page admin UI that lets
// an operator manage registered devices and handle incoming support requests
// from end-user rustdesk clients.
//
// High-level shape:
//
//   * `model`  — `RegisteredDevice`, `SupportRequest`, and the public API
//                payloads.
//   * `store`  — JSON-backed persistence under `<config_dir>/admin_store.json`.
//   * `auth`   — admin cookie sessions + HMAC helpers for public endpoints.
//   * `events` — in-process broadcast feed that the SSE endpoint streams.
//   * `api`    — axum router and request handlers.
//   * `client` — end-user side helpers used by flutter_ffi.rs.
//
// The server is opt-in via the `enable-admin-server` config option and binds
// by default to `127.0.0.1:21119` (override with `admin-web-port`).

pub mod auth;
pub mod client;
pub mod events;
pub mod model;
pub mod store;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub mod api;

use std::sync::OnceLock;

use hbb_common::{config::Config, log, ResultType};

use crate::admin::store::AdminStore;

/// Default port for the admin web console. Chosen to sit above the existing
/// rustdesk port range (21114-21119) so it never collides with the main
/// service.
pub const DEFAULT_ADMIN_PORT: u16 = 21119;

/// Global store handle. `None` until `init()` has been called or an early
/// handler triggers lazy init.
fn store_slot() -> &'static OnceLock<AdminStore> {
    static STORE: OnceLock<AdminStore> = OnceLock::new();
    &STORE
}

pub fn store() -> &'static AdminStore {
    store_slot().get_or_init(|| {
        AdminStore::open_default().unwrap_or_else(|err| {
            log::error!("admin: failed to open admin_store.json: {err}");
            // Fall back to an in-memory-only store at a throwaway path so the
            // process still boots. The file just won't persist.
            AdminStore::open_at(std::env::temp_dir().join("rustdesk_admin_store_fallback.json"))
                .expect("in-memory admin store")
        })
    })
}

/// Is the admin server enabled on this install?
pub fn is_server_enabled() -> bool {
    hbb_common::config::option2bool(
        "enable-admin-server",
        &Config::get_option("enable-admin-server"),
    )
}

pub fn bind_port() -> u16 {
    let opt = Config::get_option("admin-web-port");
    opt.parse::<u16>().unwrap_or(DEFAULT_ADMIN_PORT)
}

/// Start the admin server. Safe to call multiple times — only the first call
/// spawns the task.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn start_if_enabled() -> ResultType<()> {
    static STARTED: OnceLock<()> = OnceLock::new();
    if !is_server_enabled() {
        log::info!("admin: server disabled (enable-admin-server != 'Y')");
        return Ok(());
    }
    if STARTED.set(()).is_err() {
        return Ok(());
    }
    let port = bind_port();
    std::thread::Builder::new()
        .name("admin-server".to_owned())
        .spawn(move || {
            if let Err(err) = api::serve_blocking(port) {
                log::error!("admin: server exited with error: {err}");
            }
        })?;
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn start_if_enabled() -> ResultType<()> {
    // No admin HTTP server on mobile. The end-user client helpers in
    // `admin::client` still work for "Request Support" though.
    Ok(())
}
