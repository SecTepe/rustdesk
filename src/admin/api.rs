// HTTP API for the admin web console.
//
// Built on axum 0.7. The router is assembled in [`router`] and then started
// via [`serve_blocking`], which owns its own tokio runtime so the admin
// server is independent of the rest of rustdesk's runtimes.
//
// Routes:
//
//   * GET  /admin/                      → static index.html
//   * GET  /admin/static/*              → static CSS/JS
//   * POST /admin/api/session           → exchange OIDC token → cookie
//   * GET  /admin/api/me                → current admin info
//   * GET  /admin/api/devices           → list
//   * POST /admin/api/devices           → create
//   * PATCH/DELETE /admin/api/devices/:id
//   * GET/POST /admin/api/requests/...  → request management
//   * GET  /admin/api/events            → SSE stream
//   * POST /admin/api/public/requests   → end-user "Request Support"
//   * POST /admin/api/public/enroll     → first-heartbeat self-enroll

use std::{
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{sse::Event, IntoResponse, Response, Sse},
    routing::{get, patch, post},
    Json, Router,
};
use hbb_common::{log, tokio, ResultType};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;

use crate::admin::{
    auth::{self, AdminSession, COOKIE_TTL},
    events::{self, AdminEvent},
    model::{
        EnrollPayload, NewSupportRequest, RegisteredDevice, RequestStatus, SupportRequest,
    },
    store::{now_secs, AdminStore, DevicePatch},
};

const COOKIE_NAME: &str = "rd_admin";

#[derive(Clone)]
struct AppState {
    store: &'static AdminStore,
}

pub fn router() -> Router {
    let state = AppState {
        store: crate::admin::store(),
    };

    let api = Router::new()
        .route(
            "/session",
            post(session_login).delete(session_logout),
        )
        .route("/me", get(me_handler))
        .route("/devices", get(list_devices).post(create_device))
        .route(
            "/devices/:id",
            patch(patch_device).delete(delete_device).get(get_device),
        )
        .route("/requests", get(list_requests))
        .route("/requests/:id/approve", post(approve_request))
        .route("/requests/:id/reject", post(reject_request))
        .route("/requests/:id/close", post(close_request))
        .route("/events", get(sse_events))
        .route("/public/requests", post(public_create_request))
        .route("/public/enroll", post(public_enroll));

    Router::new()
        .route("/admin", get(index))
        .route("/admin/", get(index))
        .route("/admin/app.js", get(serve_app_js))
        .route("/admin/app.css", get(serve_app_css))
        .nest("/admin/api", api)
        .layer(CorsLayer::new().allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE]))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Start an axum server on `port` and block until it exits. Owns its own
/// current-thread tokio runtime.
pub fn serve_blocking(port: u16) -> ResultType<()> {
    let rt = hbb_common::tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        log::info!("admin: serving web console on http://{}", addr);
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(err) => {
                log::error!("admin: failed to bind {}: {}", addr, err);
                return Err::<(), _>(hbb_common::anyhow::anyhow!(
                    "bind {}: {}",
                    addr,
                    err
                ));
            }
        };
        if let Err(err) = axum::serve(listener, router().into_make_service()).await {
            log::error!("admin: server error: {}", err);
            return Err(hbb_common::anyhow::anyhow!("{}", err));
        }
        Ok(())
    })?;
    Ok(())
}

// ---------- shared helpers ----------

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

fn require_admin(headers: &HeaderMap) -> Result<AdminSession, Response> {
    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        if let Some(rest) = trimmed.strip_prefix(&format!("{}=", COOKIE_NAME)) {
            if let Some(session) = auth::lookup_cookie(rest) {
                if session.is_admin {
                    return Ok(session);
                }
                return Err(error(StatusCode::FORBIDDEN, "not an admin"));
            }
        }
    }
    Err(error(StatusCode::UNAUTHORIZED, "login required"))
}

// ---------- static assets ----------

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("web/index.html"),
    )
}

async fn serve_app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        include_str!("web/app.js"),
    )
}

async fn serve_app_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("web/app.css"),
    )
}

// ---------- session login/logout ----------

#[derive(Debug, Deserialize)]
struct SessionLoginBody {
    /// OIDC access_token previously obtained via the standard rustdesk login
    /// flow. Alternatively, when `admin-bypass-oidc` is set to `Y`, any
    /// non-empty `local_password` that matches `admin-local-password` is
    /// accepted — useful for air-gapped deployments.
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    local_password: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionLoginResponse {
    ok: bool,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

async fn session_login(
    State(_state): State<AppState>,
    Json(body): Json<SessionLoginBody>,
) -> Response {
    // Happy path: verify the OIDC access_token by asking the API server for
    // the owning AuthBody. If that lookup succeeds and `is_admin == true`, we
    // mint a cookie.
    //
    // For the v1 we reuse the OIDC _query_ mechanism already in
    // `hbbs_http::account.rs`, but the simpler `validate token vs remote`
    // path isn't exposed as a public API. As an interim solution we accept a
    // pre-validated AuthBody serialised from the caller (the admin console
    // frontend runs the OIDC redirect itself and posts back the full body).
    //
    // For completeness we ALSO support a local-password fallback for
    // deployments without OIDC at all.

    let local_ok = {
        let expected = hbb_common::config::Config::get_option("admin-local-password");
        let bypass = hbb_common::config::option2bool(
            "admin-bypass-oidc",
            &hbb_common::config::Config::get_option("admin-bypass-oidc"),
        );
        bypass
            && !expected.is_empty()
            && body.local_password.as_deref() == Some(expected.as_str())
    };

    if local_ok {
        let session = AdminSession {
            name: body.name.unwrap_or_else(|| "local-admin".into()),
            email: None,
            is_admin: true,
            expires_at: Instant::now() + COOKIE_TTL,
        };
        let token = auth::issue_cookie(session.clone());
        return build_login_response(token, session);
    }

    // OIDC token path. The frontend is expected to have already completed the
    // OIDC flow and now posts its resulting access_token. We mark the cookie
    // as admin only if the external API server says `is_admin = true`.
    let token = match body.access_token {
        Some(t) if !t.is_empty() => t,
        _ => return error(StatusCode::UNAUTHORIZED, "missing access_token"),
    };

    match verify_oidc_access_token(&token).await {
        Ok(user) => {
            if !user.is_admin {
                return error(StatusCode::FORBIDDEN, "not an admin account");
            }
            let session = AdminSession {
                name: user.name,
                email: user.email,
                is_admin: true,
                expires_at: Instant::now() + COOKIE_TTL,
            };
            let cookie = auth::issue_cookie(session.clone());
            build_login_response(cookie, session)
        }
        Err(err) => error(StatusCode::UNAUTHORIZED, format!("verify failed: {err}")),
    }
}

fn build_login_response(token: String, session: AdminSession) -> Response {
    let cookie_value = format!(
        "{}={}; Path=/admin; Max-Age={}; HttpOnly; SameSite=Strict",
        COOKIE_NAME,
        token,
        COOKIE_TTL.as_secs()
    );
    let body = SessionLoginResponse {
        ok: true,
        name: session.name.clone(),
        email: session.email.clone(),
    };
    let mut resp = (StatusCode::OK, Json(body)).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie_value).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    resp
}

async fn session_logout(headers: HeaderMap) -> Response {
    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        if let Some(rest) = trimmed.strip_prefix(&format!("{}=", COOKIE_NAME)) {
            auth::revoke_cookie(rest);
        }
    }
    (
        StatusCode::OK,
        [(
            header::SET_COOKIE,
            format!("{}=; Path=/admin; Max-Age=0", COOKIE_NAME),
        )],
        Json(json!({ "ok": true })),
    )
        .into_response()
}

/// Minimal projection of `hbbs_http::account::UserPayload` used internally.
struct VerifiedUser {
    name: String,
    email: Option<String>,
    is_admin: bool,
}

async fn verify_oidc_access_token(_access_token: &str) -> ResultType<VerifiedUser> {
    // Placeholder: the external API server does not expose a "validate this
    // existing access_token" endpoint as of rustdesk 1.4.6 — OIDC login
    // returns an AuthBody exactly once. The admin console frontend therefore
    // completes the OIDC flow itself and relays the full user object back.
    //
    // Here we accept the token string as already trusted IF we are running
    // next to an OidcSession that recently produced it. For the MVP we treat
    // any non-empty access_token matching the locally stored one as valid.
    let local = hbb_common::config::LocalConfig::get_option("access_token");
    if local.is_empty() || local != _access_token {
        hbb_common::bail!("access_token does not match local session");
    }
    let user_info = hbb_common::config::LocalConfig::get_option("user_info");
    if user_info.is_empty() {
        return Ok(VerifiedUser {
            name: "admin".into(),
            email: None,
            is_admin: true,
        });
    }
    let v: serde_json::Value = serde_json::from_str(&user_info).unwrap_or_default();
    Ok(VerifiedUser {
        name: v["name"].as_str().unwrap_or("admin").to_owned(),
        email: v["email"].as_str().map(|s| s.to_owned()),
        // The locally cached user_info doesn't carry is_admin; admins must
        // explicitly opt in by setting `admin-allow-local-token=Y`.
        is_admin: hbb_common::config::option2bool(
            "admin-allow-local-token",
            &hbb_common::config::Config::get_option("admin-allow-local-token"),
        ),
    })
}

async fn me_handler(headers: HeaderMap) -> Response {
    match require_admin(&headers) {
        Ok(session) => (
            StatusCode::OK,
            Json(json!({
                "name": session.name,
                "email": session.email,
                "is_admin": session.is_admin,
            })),
        )
            .into_response(),
        Err(resp) => resp,
    }
}

// ---------- device endpoints ----------

#[derive(Debug, Deserialize)]
struct DeviceListQuery {
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    tag: Option<String>,
}

async fn list_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DeviceListQuery>,
) -> Response {
    if let Err(resp) = require_admin(&headers) {
        return resp;
    }
    let all = state.store.list_devices();
    let filtered: Vec<RegisteredDevice> = all
        .into_iter()
        .filter(|d| match &q.search {
            Some(s) if !s.is_empty() => {
                let needle = s.to_lowercase();
                d.id.to_lowercase().contains(&needle)
                    || d.alias.to_lowercase().contains(&needle)
                    || d.hostname.to_lowercase().contains(&needle)
            }
            _ => true,
        })
        .filter(|d| match &q.tag {
            Some(t) if !t.is_empty() => d.tags.iter().any(|tag| tag == t),
            _ => true,
        })
        .collect();
    (StatusCode::OK, Json(json!({ "devices": filtered }))).into_response()
}

async fn get_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(resp) = require_admin(&headers) {
        return resp;
    }
    match state.store.get_device(&id) {
        Some(d) => (StatusCode::OK, Json(d)).into_response(),
        None => error(StatusCode::NOT_FOUND, "device not found"),
    }
}

#[derive(Debug, Deserialize)]
struct CreateDeviceBody {
    id: String,
    #[serde(default)]
    alias: String,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    owner_email: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    note: String,
}

async fn create_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateDeviceBody>,
) -> Response {
    if let Err(resp) = require_admin(&headers) {
        return resp;
    }
    if body.id.trim().is_empty() {
        return error(StatusCode::BAD_REQUEST, "id required");
    }
    let now = now_secs();
    let dev = RegisteredDevice {
        id: body.id,
        uuid: String::new(),
        alias: body.alias,
        hostname: body.hostname,
        os: body.os,
        owner_email: body.owner_email,
        tags: body.tags,
        note: body.note,
        enrolled_at: now,
        last_seen: Some(now),
    };
    match state.store.upsert_device(dev) {
        Ok(d) => {
            events::publish(AdminEvent::DeviceUpserted(d.clone()));
            (StatusCode::OK, Json(d)).into_response()
        }
        Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn patch_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(patch): Json<DevicePatch>,
) -> Response {
    if let Err(resp) = require_admin(&headers) {
        return resp;
    }
    match state.store.patch_device(&id, patch) {
        Ok(d) => {
            events::publish(AdminEvent::DeviceUpserted(d.clone()));
            (StatusCode::OK, Json(d)).into_response()
        }
        Err(err) => error(StatusCode::NOT_FOUND, err.to_string()),
    }
}

async fn delete_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(resp) = require_admin(&headers) {
        return resp;
    }
    match state.store.delete_device(&id) {
        Ok(true) => {
            events::publish(AdminEvent::DeviceRemoved { id: id.clone() });
            (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
        }
        Ok(false) => error(StatusCode::NOT_FOUND, "device not found"),
        Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

// ---------- request endpoints ----------

#[derive(Debug, Deserialize)]
struct RequestListQuery {
    #[serde(default)]
    status: Option<String>,
}

async fn list_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<RequestListQuery>,
) -> Response {
    if let Err(resp) = require_admin(&headers) {
        return resp;
    }
    let filter = q.status.as_deref().and_then(parse_status);
    let list = state.store.list_requests(filter);
    (StatusCode::OK, Json(json!({ "requests": list }))).into_response()
}

fn parse_status(s: &str) -> Option<RequestStatus> {
    match s {
        "pending" => Some(RequestStatus::Pending),
        "approved" => Some(RequestStatus::Approved),
        "rejected" => Some(RequestStatus::Rejected),
        "connected" => Some(RequestStatus::Connected),
        "closed" => Some(RequestStatus::Closed),
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
struct RejectBody {
    #[serde(default)]
    reason: Option<String>,
}

async fn approve_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let session = match require_admin(&headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let who = session.email.clone().unwrap_or(session.name.clone());
    match state.store.update_request_status(
        &id,
        RequestStatus::Approved,
        Some(who),
        None,
        now_secs(),
    ) {
        Ok(req) => {
            events::publish(AdminEvent::RequestUpdated(req.clone()));
            (StatusCode::OK, Json(req)).into_response()
        }
        Err(err) => error(StatusCode::NOT_FOUND, err.to_string()),
    }
}

async fn reject_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<RejectBody>,
) -> Response {
    let session = match require_admin(&headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let who = session.email.clone().unwrap_or(session.name.clone());
    match state.store.update_request_status(
        &id,
        RequestStatus::Rejected,
        Some(who),
        body.reason,
        now_secs(),
    ) {
        Ok(req) => {
            events::publish(AdminEvent::RequestUpdated(req.clone()));
            (StatusCode::OK, Json(req)).into_response()
        }
        Err(err) => error(StatusCode::NOT_FOUND, err.to_string()),
    }
}

async fn close_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let session = match require_admin(&headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let who = session.email.clone().unwrap_or(session.name.clone());
    match state.store.update_request_status(
        &id,
        RequestStatus::Closed,
        Some(who),
        None,
        now_secs(),
    ) {
        Ok(req) => {
            events::publish(AdminEvent::RequestUpdated(req.clone()));
            (StatusCode::OK, Json(req)).into_response()
        }
        Err(err) => error(StatusCode::NOT_FOUND, err.to_string()),
    }
}

// ---------- public endpoints (end-user clients) ----------

async fn public_create_request(
    State(state): State<AppState>,
    Json(body): Json<NewSupportRequest>,
) -> Response {
    let message = format!("{}|{}|{}", body.device_id, body.device_uuid, body.timestamp);
    if !auth::verify_signature(&message, &body.signature, body.timestamp) {
        return error(StatusCode::UNAUTHORIZED, "bad signature");
    }
    if body.device_id.trim().is_empty() {
        return error(StatusCode::BAD_REQUEST, "device_id required");
    }

    let now = now_secs();
    let req = SupportRequest {
        id: Uuid::new_v4().to_string(),
        device_id: body.device_id,
        device_uuid: body.device_uuid,
        requester_name: body.requester_name,
        reason: body.reason,
        created_at: now,
        status: RequestStatus::Pending,
        approved_by: None,
        handled_at: None,
        connection_log_id: None,
        reject_reason: None,
    };
    match state.store.push_request(req.clone()) {
        Ok(stored) => {
            events::publish(AdminEvent::RequestCreated(stored.clone()));
            let _ = state.store.touch_device(&stored.device_id, now);
            (StatusCode::OK, Json(json!({ "ok": true, "id": stored.id }))).into_response()
        }
        Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn public_enroll(
    State(state): State<AppState>,
    Json(body): Json<EnrollPayload>,
) -> Response {
    let message = format!("{}|{}|{}", body.id, body.uuid, body.timestamp);
    if !auth::verify_signature(&message, &body.signature, body.timestamp) {
        return error(StatusCode::UNAUTHORIZED, "bad signature");
    }
    let now = now_secs();
    let dev = RegisteredDevice::new_enrolled(body.id, body.uuid, body.hostname, body.os, now);
    match state.store.upsert_device(dev) {
        Ok(d) => {
            events::publish(AdminEvent::DeviceUpserted(d.clone()));
            (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
        }
        Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

// ---------- SSE ----------

async fn sse_events(headers: HeaderMap) -> Response {
    if let Err(resp) = require_admin(&headers) {
        return resp;
    }
    let rx = events::subscribe();
    let stream = BroadcastStream::new(rx).map(|item| -> Result<Event, Infallible> {
        match item {
            Ok(event) => {
                let payload = serde_json::to_string(&event).unwrap_or_else(|_| "{}".into());
                Ok(Event::default().event("update").data(payload))
            }
            Err(err) => {
                log::warn!("admin: SSE recv error: {err}");
                Ok(Event::default().event("lagged").data("{}"))
            }
        }
    });
    Sse::new(stream)
        .keep_alive(
            axum::response::sse::KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response()
}
