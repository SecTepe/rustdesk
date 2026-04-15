// RustDesk admin console SPA. Plain vanilla JS — no build step.
// All endpoints live under /admin/api. Auth is cookie-based; the browser
// just needs to POST /admin/api/session once.

const API = "/admin/api";
let eventSource = null;
let cachedRequests = [];
let cachedDevices = [];

function $(sel) { return document.querySelector(sel); }
function $$(sel) { return Array.from(document.querySelectorAll(sel)); }

async function api(path, opts = {}) {
  const headers = opts.headers || {};
  if (opts.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  const res = await fetch(API + path, { credentials: "same-origin", ...opts, headers });
  if (res.status === 401) {
    showLogin();
    throw new Error("unauthorized");
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${text}`);
  }
  if (res.headers.get("content-type")?.includes("application/json")) return res.json();
  return res.text();
}

function showLogin() {
  $("#login-view").hidden = false;
  $("#app-view").hidden = true;
  if (eventSource) { eventSource.close(); eventSource = null; }
}
function showApp(name, email) {
  $("#login-view").hidden = true;
  $("#app-view").hidden = false;
  $("#session-info").textContent = email ? `${name} <${email}>` : name;
  refreshRequests();
  refreshDevices();
  subscribeEvents();
}

async function tryLogin() {
  $("#login-error").textContent = "";
  const name = $("#login-name").value.trim();
  const access_token = $("#login-token").value.trim();
  const local_password = $("#login-local").value;
  try {
    const body = JSON.stringify({ name, access_token, local_password });
    const res = await api("/session", { method: "POST", body });
    showApp(res.name, res.email);
  } catch (err) {
    $("#login-error").textContent = err.message;
  }
}

async function boot() {
  try {
    const me = await api("/me");
    showApp(me.name, me.email);
  } catch (_) {
    showLogin();
  }
}

// ---------- requests ----------

function fmtDate(ts) {
  if (!ts) return "";
  return new Date(ts * 1000).toLocaleString();
}

function renderRequests() {
  const tbody = $("#requests-table tbody");
  tbody.innerHTML = "";
  const filter = $("#request-status-filter").value;
  const rows = cachedRequests
    .filter(r => !filter || r.status === filter)
    .sort((a, b) => b.created_at - a.created_at);
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escape(r.device_id)}</td>
      <td>${escape(r.requester_name || "")}</td>
      <td>${escape(r.reason || "")}</td>
      <td>${fmtDate(r.created_at)}</td>
      <td><span class="badge ${r.status}">${r.status}</span></td>
      <td>
        ${r.status === "pending" ? `
          <button class="primary" data-action="approve" data-id="${r.id}">Approve</button>
          <button class="danger"  data-action="reject"  data-id="${r.id}">Reject</button>
        ` : r.status === "approved" || r.status === "connected" ? `
          <button data-action="close" data-id="${r.id}">Close</button>
        ` : ""}
      </td>`;
    tbody.appendChild(tr);
  }
}

async function refreshRequests() {
  try {
    const res = await api("/requests");
    cachedRequests = res.requests || [];
    renderRequests();
  } catch (err) { console.error(err); }
}

async function handleRequestAction(action, id) {
  try {
    if (action === "approve") await api(`/requests/${id}/approve`, { method: "POST" });
    if (action === "reject") {
      const reason = prompt("Reason for rejection (optional):", "");
      if (reason === null) return;
      await api(`/requests/${id}/reject`, {
        method: "POST",
        body: JSON.stringify({ reason }),
      });
    }
    if (action === "close") await api(`/requests/${id}/close`, { method: "POST" });
    await refreshRequests();
  } catch (err) { alert(err.message); }
}

// ---------- devices ----------

function renderDevices() {
  const tbody = $("#devices-table tbody");
  tbody.innerHTML = "";
  const search = $("#device-search").value.trim().toLowerCase();
  const rows = cachedDevices.filter(d => {
    if (!search) return true;
    return (d.id + d.alias + d.hostname).toLowerCase().includes(search);
  });
  for (const d of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escape(d.id)}</td>
      <td>${escape(d.alias || "")}</td>
      <td>${escape(d.hostname || "")}</td>
      <td>${escape(d.os || "")}</td>
      <td>${escape(d.owner_email || "")}</td>
      <td>${(d.tags || []).map(t => `<span class="badge closed">${escape(t)}</span>`).join(" ")}</td>
      <td>${fmtDate(d.last_seen)}</td>
      <td>
        <button data-action="edit-device" data-id="${d.id}">Edit</button>
        <button class="danger" data-action="delete-device" data-id="${d.id}">Delete</button>
      </td>`;
    tbody.appendChild(tr);
  }
}

async function refreshDevices() {
  try {
    const res = await api("/devices");
    cachedDevices = res.devices || [];
    renderDevices();
  } catch (err) { console.error(err); }
}

async function addDevice() {
  const id = prompt("RustDesk ID:");
  if (!id) return;
  const alias = prompt("Alias:", "") || "";
  const owner_email = prompt("Owner email:", "") || "";
  try {
    await api("/devices", { method: "POST", body: JSON.stringify({ id, alias, owner_email }) });
    await refreshDevices();
  } catch (err) { alert(err.message); }
}

async function editDevice(id) {
  const d = cachedDevices.find(x => x.id === id);
  if (!d) return;
  const alias = prompt("Alias:", d.alias || "");
  if (alias === null) return;
  const owner_email = prompt("Owner email:", d.owner_email || "");
  if (owner_email === null) return;
  const tags = prompt("Tags (comma-separated):", (d.tags || []).join(","));
  if (tags === null) return;
  try {
    await api(`/devices/${id}`, {
      method: "PATCH",
      body: JSON.stringify({
        alias,
        owner_email,
        tags: tags.split(",").map(s => s.trim()).filter(Boolean),
      }),
    });
    await refreshDevices();
  } catch (err) { alert(err.message); }
}

async function deleteDevice(id) {
  if (!confirm(`Delete device ${id}?`)) return;
  try {
    await api(`/devices/${id}`, { method: "DELETE" });
    await refreshDevices();
  } catch (err) { alert(err.message); }
}

// ---------- live events ----------

function subscribeEvents() {
  if (eventSource) eventSource.close();
  eventSource = new EventSource(API + "/events");
  eventSource.addEventListener("update", (ev) => {
    try {
      const payload = JSON.parse(ev.data);
      applyEvent(payload);
    } catch (_) {}
  });
  eventSource.onerror = () => {
    console.warn("admin SSE disconnected, reconnecting in 3s");
    setTimeout(subscribeEvents, 3000);
  };
}

function applyEvent(ev) {
  switch (ev.kind) {
    case "request_created":
      cachedRequests.push(ev.payload);
      renderRequests();
      break;
    case "request_updated": {
      const i = cachedRequests.findIndex(r => r.id === ev.payload.id);
      if (i >= 0) cachedRequests[i] = ev.payload; else cachedRequests.push(ev.payload);
      renderRequests();
      break;
    }
    case "device_upserted": {
      const i = cachedDevices.findIndex(d => d.id === ev.payload.id);
      if (i >= 0) cachedDevices[i] = ev.payload; else cachedDevices.push(ev.payload);
      renderDevices();
      break;
    }
    case "device_removed":
      cachedDevices = cachedDevices.filter(d => d.id !== ev.payload.id);
      renderDevices();
      break;
  }
}

// ---------- utilities ----------

function escape(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ---------- wiring ----------

document.addEventListener("DOMContentLoaded", () => {
  $("#login-btn").addEventListener("click", tryLogin);
  $("#refresh-requests").addEventListener("click", refreshRequests);
  $("#refresh-devices").addEventListener("click", refreshDevices);
  $("#request-status-filter").addEventListener("change", renderRequests);
  $("#device-search").addEventListener("input", renderDevices);
  $("#add-device-btn").addEventListener("click", addDevice);
  $("#logout-btn").addEventListener("click", async () => {
    try { await api("/session", { method: "DELETE" }); } catch (_) {}
    showLogin();
  });
  $$("nav button[data-tab]").forEach(btn => {
    btn.addEventListener("click", () => {
      $$("nav button[data-tab]").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const tab = btn.dataset.tab;
      $("#tab-requests").hidden = tab !== "requests";
      $("#tab-devices").hidden = tab !== "devices";
    });
  });
  document.addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-action]");
    if (!btn) return;
    const { action, id } = btn.dataset;
    if (action === "approve" || action === "reject" || action === "close") {
      handleRequestAction(action, id);
    } else if (action === "edit-device") {
      editDevice(id);
    } else if (action === "delete-device") {
      deleteDevice(id);
    }
  });
  boot();
});
