(function (global) {
  "use strict";

  const SIEM = {};

  async function getJson(url) {
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) {
      const txt = await res.text();
      throw new Error(`GET ${url} failed: ${res.status} ${txt}`);
    }
    return res.json();
  }

  async function postJson(url, payload) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload || {}),
    });
    if (!res.ok) {
      const txt = await res.text();
      throw new Error(`POST ${url} failed: ${res.status} ${txt}`);
    }
    return res.json();
  }

  async function deleteJson(url) {
    const res = await fetch(url, { method: "DELETE", headers: { Accept: "application/json" } });
    if (!res.ok) {
      const txt = await res.text();
      throw new Error(`DELETE ${url} failed: ${res.status} ${txt}`);
    }
    return res.json();
  }

  SIEM.getJson = getJson;
  SIEM.postJson = postJson;
  SIEM.deleteJson = deleteJson;

  function ensureToastHost() {
    let host = document.getElementById("toast-host");
    if (!host) {
      host = document.createElement("div");
      host.id = "toast-host";
      host.className = "toast-host";
      document.body.appendChild(host);
    }
    return host;
  }

  function showToast(message, kind = "info", opts = {}) {
    const host = ensureToastHost();
    const toast = document.createElement("div");
    toast.className = `toast kind-${kind}`;
    const body = document.createElement("div");
    body.className = "body";
    body.textContent = message;
    toast.appendChild(body);

    const actions = document.createElement("div");
    actions.className = "actions";
    const closeBtn = document.createElement("button");
    closeBtn.className = "ghost";
    closeBtn.textContent = "Dismiss";
    closeBtn.addEventListener("click", () => toast.remove());
    actions.appendChild(closeBtn);
    toast.appendChild(actions);

    host.appendChild(toast);
    const ttl = opts.ttl || 5000;
    if (ttl > 0) {
      setTimeout(() => toast.remove(), ttl);
    }
    return toast;
  }

  function confirmToast(message, opts = {}) {
    return new Promise((resolve) => {
      const host = ensureToastHost();
      const toast = document.createElement("div");
      toast.className = "toast kind-confirm";
      const body = document.createElement("div");
      body.className = "body";
      body.textContent = message;
      toast.appendChild(body);

      const actions = document.createElement("div");
      actions.className = "actions";

      const cancelBtn = document.createElement("button");
      cancelBtn.className = "ghost";
      cancelBtn.textContent = opts.cancelLabel || "Cancel";
      cancelBtn.addEventListener("click", () => {
        toast.remove();
        resolve(false);
      });

      const confirmBtn = document.createElement("button");
      confirmBtn.className = opts.danger ? "danger" : "primary";
      confirmBtn.textContent = opts.confirmLabel || "Confirm";
      confirmBtn.addEventListener("click", () => {
        toast.remove();
        resolve(true);
      });

      actions.appendChild(cancelBtn);
      actions.appendChild(confirmBtn);
      toast.appendChild(actions);
      host.appendChild(toast);
    });
  }

  SIEM.showToast = showToast;
  SIEM.confirmToast = confirmToast;

  function poll(url, everyMs, onTick, { immediate = true } = {}) {
    let active = true;
    async function tick() {
      if (!active) return;
      try {
        const data = await getJson(url);
        if (active) onTick(data);
      } catch (err) {
        console.warn("poll error:", err);
        updateLive("stale");
      }
      if (active) setTimeout(tick, everyMs);
    }
    if (immediate) tick();
    else setTimeout(tick, everyMs);
    return () => {
      active = false;
    };
  }

  SIEM.poll = poll;

  function updateLive(state) {
    const dot = document.querySelector(".live-dot");
    const label = document.querySelector(".live-label");
    if (!dot || !label) return;
    if (state === "stale") {
      dot.classList.add("stale");
      label.textContent = "Offline";
    } else {
      dot.classList.remove("stale");
      const now = new Date();
      label.textContent = `Live - updated ${now.toLocaleTimeString()}`;
    }
  }

  SIEM.updateLive = updateLive;

  function humanTime(iso) {
    if (!iso) return "-";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  }

  function relativeTime(iso) {
    if (!iso) return "-";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    const diff = (Date.now() - d.getTime()) / 1000;
    if (diff < 60) return `${Math.round(diff)}s ago`;
    if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
    return `${Math.round(diff / 86400)}d ago`;
  }

  function titleCase(s) {
    if (!s) return "";
    return String(s)
      .replace(/_/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
  }

  function severityChip(sev) {
    const s = String(sev || "").toLowerCase();
    const cls = s === "high" ? "sev-high" : s === "medium" ? "sev-medium" : s === "low" ? "sev-low" : "kind-muted";
    return `<span class="chip ${cls}"><span class="dot"></span>${titleCase(s || "unknown")}</span>`;
  }

  SIEM.humanTime = humanTime;
  SIEM.relativeTime = relativeTime;
  SIEM.titleCase = titleCase;
  SIEM.severityChip = severityChip;

  function setQueryParam(key, value) {
    const url = new URL(window.location.href);
    if (value === null || value === undefined || value === "") {
      url.searchParams.delete(key);
    } else if (Array.isArray(value)) {
      url.searchParams.delete(key);
      value.forEach((v) => url.searchParams.append(key, v));
    } else {
      url.searchParams.set(key, value);
    }
    window.history.replaceState({}, "", url.toString());
  }

  SIEM.setQueryParam = setQueryParam;

  function selectedIds(selector) {
    return Array.from(document.querySelectorAll(`${selector}:checked`)).map((el) => el.value);
  }

  function toggleAll(selector, checked) {
    document.querySelectorAll(selector).forEach((el) => (el.checked = checked));
  }

  SIEM.selectedIds = selectedIds;
  SIEM.toggleAll = toggleAll;

  async function executeAction(actionType, targetIds, opts = {}) {
    const dryRun = opts.dryRun === true;
    const reason = opts.reason || "";
    const directValue = opts.directValue || "";
    const requestedBy = opts.requestedBy || "dashboard";
    const confirmText =
      opts.confirmText ||
      `Run '${titleCase(actionType)}' on ${targetIds.length || (directValue ? 1 : 0)} item(s)?`;
    if (!opts.skipConfirm) {
      const ok = await confirmToast(confirmText, { danger: true, confirmLabel: "Run" });
      if (!ok) return null;
    }
    const result = await postJson("/api/actions/execute", {
      action_type: actionType,
      target_ids: targetIds,
      dry_run: dryRun,
      requested_by: requestedBy,
      reason,
      direct_value: directValue,
    });
    const status = result.status || "completed";
    const summary = describeAction(result);
    showToast(`${titleCase(actionType)} - ${status}${summary ? ` (${summary})` : ""}`, status.includes("fail") ? "err" : "ok");
    return result;
  }

  function describeAction(action) {
    const details = action.details || {};
    if (details.blocked) return `${details.blocked.length} IP(s) blocked`;
    if (details.unblocked) return `${details.unblocked.length} IP(s) unblocked`;
    if (details.quarantined) return `${details.quarantined.length} host(s) isolated`;
    if (details.released) return `${details.released.length} host(s) released`;
    if (details.attempted_pids)
      return `${details.attempted_pids.length - (details.failed || []).length}/${details.attempted_pids.length} PIDs`;
    if (details.result) return details.result;
    return "";
  }

  SIEM.executeAction = executeAction;
  SIEM.describeAction = describeAction;

  document.addEventListener("DOMContentLoaded", () => {
    ensureToastHost();
    updateLive("live");
  });

  global.SIEM = SIEM;
})(window);
