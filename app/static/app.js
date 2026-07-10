// No framework, no build step — this is a handful of small, self-contained
// behaviors, not an app. Keep additions here small and readable.

function toast(message) {
  let region = document.getElementById("toast-region");
  if (!region) {
    region = document.createElement("div");
    region.id = "toast-region";
    document.body.appendChild(region);
  }
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = message;
  region.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

// ---- tabs: [data-tabs] wraps [data-tab-btn=id] buttons and [data-tab-panel=id] panels ----
function initTabs() {
  document.querySelectorAll("[data-tabs]").forEach((group) => {
    const buttons = group.querySelectorAll("[data-tab-btn]");
    buttons.forEach((btn) => {
      btn.addEventListener("click", () => {
        const target = btn.getAttribute("data-tab-btn");
        group.querySelectorAll("[data-tab-btn]").forEach((b) => b.classList.remove("active"));
        group.querySelectorAll("[data-tab-panel]").forEach((p) => p.classList.remove("active"));
        btn.classList.add("active");
        const panel = group.querySelector(`[data-tab-panel="${target}"]`);
        if (panel) panel.classList.add("active");
      });
    });
  });
}

// ---- copy-to-clipboard on any [data-copy] element ----
function initCopyButtons() {
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const value = btn.getAttribute("data-copy");
      try {
        await navigator.clipboard.writeText(value);
        toast("Copied to clipboard");
      } catch {
        toast("Copy failed — select and copy manually");
      }
    });
  });
}

// ---- scan status polling: if #scan-status-poll exists with data-program-id,
// poll every 4s while status is queued/running, then reload once to show results ----
function initScanPolling() {
  const el = document.getElementById("scan-status-poll");
  if (!el) return;
  const programId = el.getAttribute("data-program-id");

  const poll = async () => {
    try {
      const res = await fetch(`/programs/${programId}/status.json`);
      if (!res.ok) return;
      const data = await res.json();
      if (data.status === "completed" || data.status === "failed") {
        toast(data.status === "completed" ? "Scan completed — refreshing" : "Scan failed — refreshing");
        setTimeout(() => window.location.reload(), 900);
        return;
      }
      setTimeout(poll, 4000);
    } catch {
      setTimeout(poll, 6000);
    }
  };
  poll();
}

// ---- lightweight client-side table filter: input[data-filter-target=tableId] ----
function initTableFilters() {
  document.querySelectorAll("[data-filter-target]").forEach((input) => {
    const table = document.getElementById(input.getAttribute("data-filter-target"));
    if (!table) return;
    input.addEventListener("input", () => {
      const q = input.value.trim().toLowerCase();
      table.querySelectorAll("tbody tr").forEach((row) => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? "" : "none";
      });
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initCopyButtons();
  initScanPolling();
  initTableFilters();
});
