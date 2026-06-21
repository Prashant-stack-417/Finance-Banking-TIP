const resultTitle = document.getElementById("resultTitle");
const resultMeta = document.getElementById("resultMeta");
const resultStatus = document.getElementById("resultStatus");
const resultContent = document.getElementById("resultContent");
const connectionStatus = document.getElementById("connectionStatus");

const endpoints = {
  indicators: "/api/indicators",
  logs: "/api/logs",
  stats: "/api/stats",
  highRiskIps: "/api/high-risk-ips",
  highRiskStats: "/api/high-risk-stats",
  rules: "/api/rules",
  lookup: (value) => `/api/indicators/${encodeURIComponent(value)}`,
  rollback: "/api/rollback",
};

function setResult(title, meta, status, content) {
  resultTitle.textContent = title;
  resultMeta.textContent = meta;
  resultStatus.textContent = status;
  resultContent.innerHTML = content;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatValue(value) {
  if (value === null || value === undefined) {
    return "-";
  }
  if (Array.isArray(value)) {
    return value.length ? value.map((entry) => formatValue(entry)).join(", ") : "-";
  }
  if (typeof value === "object") {
    return escapeHtml(JSON.stringify(value));
  }
  return escapeHtml(value);
}

function badgeForValue(value) {
  if (typeof value === "boolean") {
    return value ? '<span class="badge bad">true</span>' : '<span class="badge ok">false</span>';
  }

  if (typeof value === "number") {
    if (value >= 90) {
      return `<span class="badge bad">${escapeHtml(value)}</span>`;
    }
    if (value >= 70) {
      return `<span class="badge warn">${escapeHtml(value)}</span>`;
    }
    return `<span class="badge ok">${escapeHtml(value)}</span>`;
  }

  return escapeHtml(value);
}

function renderObject(obj) {
  const entries = Object.entries(obj || {});
  if (!entries.length) {
    return '<div class="empty-state">No data returned.</div>';
  }

  const meta = entries
    .filter(([, value]) => typeof value !== "object" || value === null)
    .slice(0, 6)
    .map(([key, value]) => `<span class="badge ok">${escapeHtml(key)}: ${formatValue(value)}</span>`)
    .join("");

  const rows = entries
    .map(([key, value]) => `
      <tr>
        <th>${escapeHtml(key)}</th>
        <td>${formatValue(value)}</td>
      </tr>
    `)
    .join("");

  return `
    ${meta ? `<div class="meta-row">${meta}</div>` : ""}
    <div class="table-wrap">
      <table>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function renderRows(items) {
  if (!Array.isArray(items) || !items.length) {
    return '<div class="empty-state">No rows matched the current filters.</div>';
  }

  const keys = Array.from(
    items.reduce((set, item) => {
      Object.keys(item || {}).forEach((key) => set.add(key));
      return set;
    }, new Set())
  );

  const head = keys.map((key) => `<th>${escapeHtml(key)}</th>`).join("");
  const body = items
    .map((item) => `
      <tr>
        ${keys.map((key) => `<td>${badgeForValue(item?.[key])}</td>`).join("")}
      </tr>
    `)
    .join("");

  return `
    <div class="table-wrap">
      <table>
        <thead><tr>${head}</tr></thead>
        <tbody>${body}</tbody>
      </table>
    </div>
  `;
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    headers: {
      Accept: "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = payload.error || response.statusText || "Request failed";
    throw new Error(message);
  }

  return payload;
}

function buildQuery(params) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== "" && value !== null && value !== undefined) {
      query.set(key, value);
    }
  });
  const string = query.toString();
  return string ? `?${string}` : "";
}

function readNumber(id) {
  const raw = document.getElementById(id).value;
  return raw === "" ? "" : String(raw);
}

function readText(id) {
  return document.getElementById(id).value.trim();
}

async function loadStats() {
  try {
    const [stats, highRisk] = await Promise.all([
      fetchJson(endpoints.stats),
      fetchJson(endpoints.highRiskStats),
    ]);

    document.getElementById("totalIndicators").textContent = stats.total ?? 0;
    document.getElementById("blockedIndicators").textContent = stats.blocked ?? 0;
    document.getElementById("highRiskIndicators").textContent = stats.high_risk ?? 0;
    document.getElementById("highRiskIps").textContent = highRisk.total_high_risk ?? 0;
    connectionStatus.textContent = "API connected";
    connectionStatus.className = "status-pill";
  } catch (error) {
    connectionStatus.textContent = `API error: ${error.message}`;
    connectionStatus.className = "status-pill";
  }
}

async function loadIndicators() {
  const url = endpoints.indicators + buildQuery({
    type: readText("indicatorType"),
    blocked: readText("indicatorBlocked"),
    min_score: readNumber("indicatorMinScore"),
    source: readText("indicatorSource"),
    limit: readNumber("indicatorLimit") || 25,
  });

  setResult("Indicators", url, "Loading indicators...", '<div class="empty-state">Fetching indicators...</div>');
  const data = await fetchJson(url);
  setResult("Indicators", url, `Loaded ${data.length} indicators`, renderRows(data));
}

async function loadLogs() {
  const url = endpoints.logs + buildQuery({
    action: readText("logAction"),
    limit: readNumber("logLimit") || 25,
  });

  setResult("Logs", url, "Loading logs...", '<div class="empty-state">Fetching enforcement logs...</div>');
  const data = await fetchJson(url);
  setResult("Logs", url, `Loaded ${data.length} log entries`, renderRows(data));
}

async function loadRules() {
  const url = endpoints.rules;
  setResult("Rules", url, "Loading rules...", '<div class="empty-state">Fetching iptables rules...</div>');
  const data = await fetchJson(url);
  setResult("Rules", url, "Current TIP rules", renderObject(data));
}

async function loadHighRiskIps() {
  const url = endpoints.highRiskIps + buildQuery({
    filter: readText("highRiskFilter"),
    source: readText("highRiskSource"),
    tag: readText("highRiskTag"),
    recent_hours: readNumber("highRiskRecentHours"),
    threshold: readNumber("highRiskThreshold") || 70,
    limit: readNumber("highRiskLimit") || 25,
  });

  setResult("High-risk IPs", url, "Loading high-risk IPs...", '<div class="empty-state">Fetching high-risk IPs...</div>');
  const data = await fetchJson(url);
  setResult(
    "High-risk IPs",
    url,
    `Loaded ${data.count ?? 0} IPs`,
    renderObject({
      count: data.count,
      threshold: data.threshold,
      filter: data.filter,
      ips: data.ips,
    })
  );
}

async function lookupIndicator() {
  const value = readText("lookupValue");
  if (!value) {
    setResult("Indicator lookup", "", "Enter a value first", '<div class="empty-state">Provide an indicator value to look up.</div>');
    return;
  }

  const url = endpoints.lookup(value);
  setResult("Indicator lookup", url, "Loading indicator...", '<div class="empty-state">Fetching indicator details...</div>');
  const data = await fetchJson(url);
  setResult("Indicator lookup", url, "Indicator found", renderObject(data));
}

async function submitRollback() {
  const value = readText("lookupValue");
  const type = readText("rollbackType");
  const ruleId = readText("rollbackRuleId");
  const analyst = readText("rollbackAnalyst") || "SOC";

  if (!value || !type || !ruleId) {
    setResult(
      "Rollback",
      endpoints.rollback,
      "Missing fields",
      '<div class="empty-state">Rollback requires value, type, and rule ID.</div>'
    );
    return;
  }

  setResult("Rollback", endpoints.rollback, "Submitting rollback...", '<div class="empty-state">Sending rollback request...</div>');
  const payload = await fetchJson(endpoints.rollback, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ value, type, rule_id: ruleId, analyst }),
  });
  setResult("Rollback", endpoints.rollback, payload.status || "Rollback complete", renderObject(payload));
}

async function runAction(action) {
  try {
    if (action === "indicators") {
      await loadIndicators();
    } else if (action === "logs") {
      await loadLogs();
    } else if (action === "rules") {
      await loadRules();
    } else if (action === "high-risk") {
      await loadHighRiskIps();
    } else if (action === "lookup") {
      await lookupIndicator();
    } else if (action === "rollback") {
      await submitRollback();
    }
  } catch (error) {
    setResult("Request failed", action, error.message, `<div class="empty-state">${escapeHtml(error.message)}</div>`);
  }
}

document.querySelectorAll("button[data-action]").forEach((button) => {
  button.addEventListener("click", () => runAction(button.dataset.action));
});

loadStats();
