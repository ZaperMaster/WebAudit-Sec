// Lógica de la interfaz de WebAudit Sec.

const POLL_INTERVAL_MS = 500;
const STAT_IDS = [
  "httpValue", "findingsValue",
  "checksPass", "checksWarning", "checksUnknown",
  "highValue", "mediumValue", "lowValue", "infoValue"
];

let lang = "es";
let statusKey = null;  // Clave de texto del estado actual (scanning, done...)
// Último análisis mostrado: { state, result, finishedAt, historyId } o { error }.
// Se repinta al cambiar de idioma y es el que se exporta.
let lastScan = null;
const el = id => document.getElementById(id);
const t = () => translations[lang];

// --- Idioma ------------------------------------------------------------------

function applyTranslations() {
  const texts = t();
  document.documentElement.lang = lang;
  Object.entries(texts).forEach(([key, value]) => {
    if (typeof value === "string" && el(key)) el(key).textContent = value;
  });
}

/**
 * Traduce un texto generado por el escáner (que llega en español).
 * `item.i18n[field]` trae la plantilla y sus datos cuando el texto los tiene;
 * si no, el texto se busca tal cual en SCANNER_TEXT_EN (i18n-scanner.js).
 */
function localize(text, item = null, field = "") {
  if (lang === "es" || !text) return text;
  const i18n = item && item.i18n && item.i18n[field];
  const english = SCANNER_TEXT_EN[i18n ? i18n.template : text];
  if (!english) return text;
  return i18n ? formatText(english, i18n.params) : english;
}

el("language").addEventListener("click", () => {
  lang = lang === "es" ? "en" : "es";
  applyTranslations();
  if (statusKey) el("statusValue").textContent = t()[statusKey];
  if (el("cancelButton").disabled) el("cancelButton").textContent = t().cancelling;
  if (lastScan) renderScan(lastScan);
  document.dispatchEvent(new Event("languagechange"));
});

// --- Utilidades DOM -------------------------------------------------------------

function addText(parent, tag, text, className = "") {
  const node = document.createElement(tag);
  node.textContent = text;
  if (className) node.className = className;
  parent.appendChild(node);
  return node;
}

function severityLabel(severity) {
  return t().severities[severity] || (severity || "").toUpperCase();
}

function addBadge(parent, severity) {
  if (!severity) return;
  addText(parent, "span", severityLabel(severity), "badge sev-" + severity);
}

/** Crea un grupo plegable <details> con título y contador. Devuelve su contenedor. */
function addGroup(parent, label, meta, labelClass = "") {
  const group = document.createElement("details");
  group.className = "report-group";
  const summary = document.createElement("summary");
  addText(summary, "span", label, ("group-label " + labelClass).trim());
  addText(summary, "span", meta, "group-meta");
  group.appendChild(summary);

  const content = document.createElement("div");
  content.className = "group-content";
  group.appendChild(content);
  parent.appendChild(group);
  return content;
}

function groupBy(items, keyOf, initialKeys = []) {
  const groups = new Map(initialKeys.map(key => [key, []]));
  items.forEach(item => {
    const key = keyOf(item);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  });
  return groups;
}

// --- Resumen -----------------------------------------------------------------

function setStatus(key) {
  statusKey = key;
  el("statusValue").textContent = t()[key];
}

function resetResults() {
  lastScan = null;
  el("exportActions").hidden = true;
  el("findingsToolbar").hidden = true;
  el("comparison").replaceChildren();
  el("exportStatus").textContent = "";
  setStatus("scanning");
  STAT_IDS.forEach(id => { el(id).textContent = "—"; });
  el("results").replaceChildren();
  el("checksList").replaceChildren();
}

/** Pinta un análisis terminado (ver lastScan). */
function renderScan(scan) {
  el("results").replaceChildren();
  el("checksList").replaceChildren();
  el("comparison").replaceChildren();
  el("exportActions").hidden = !scan.result;
  el("findingsToolbar").hidden = true;  // renderFindings la muestra si hay hallazgos
  if (scan.error) {
    setStatus("error");
    addText(el("results"), "p", localize(scan.error));
    return;
  }
  renderSummary(scan.result);
  setStatus(scan.state === "cancelled" ? "cancelled" : "done");
  renderChecks(scan.result.checks || []);
  renderFindings(scan.result);
}

function renderSummary(data) {
  const summary = data.summary || {};
  el("httpValue").textContent = data.http_status;
  el("findingsValue").textContent = data.findings_count;
  el("highValue").textContent = summary.high ?? 0;
  el("mediumValue").textContent = summary.medium ?? 0;
  el("lowValue").textContent = summary.low ?? 0;
  el("infoValue").textContent = summary.info ?? 0;
}

// --- Comprobaciones ----------------------------------------------------------------

function renderChecks(checks) {
  const texts = t();
  const list = el("checksList");
  const counts = { pass: 0, warning: 0, fail: 0, unknown: 0 };

  if (!checks.length) {
    addText(list, "p", texts.noChecks);
  }

  const byCategory = groupBy(checks, check => check.category || "configuration");
  byCategory.forEach((categoryChecks, category) => {
    const content = addGroup(
      list,
      texts.categories[category] || category,
      categoryChecks.length + " " + texts.checksCount
    );

    categoryChecks.forEach(check => {
      const status = texts.statuses[check.status] ? check.status : "unknown";
      if (status in counts) counts[status]++;

      const item = document.createElement("article");
      item.className = "finding";
      const head = document.createElement("div");
      head.className = "finding-head";
      addText(head, "strong", texts.statuses[status], "status-" + status);
      addBadge(head, check.severity);
      item.appendChild(head);
      addText(item, "h3", localize(check.title, check, "title") || check.id || texts.defaultCheckTitle);
      if (check.details) addText(item, "p", localize(check.details, check, "details"));
      content.appendChild(item);
    });
  });

  el("checksPass").textContent = counts.pass;
  el("checksWarning").textContent = counts.warning + counts.fail;
  el("checksUnknown").textContent = counts.unknown;
}

// --- Hallazgos -------------------------------------------------------------------

function crawlTitle(data) {
  const texts = t();
  if ((data.crawl_stop_reasons || []).includes("cancelled")) return texts.cancelledTitle;
  if (data.page_limit === 1) return texts.singlePageComplete;
  return data.crawl_complete ? texts.crawlComplete : texts.crawlIncomplete;
}

// renderFindings y la vista de hallazgos están en findings.js.

// --- Opciones del análisis ---------------------------------------------------------
// Límites del rastreo y búsqueda de archivos expuestos. Se recuerdan en este
// navegador (si el almacenamiento local no está disponible, se usan los valores por defecto).

const OPTION_INPUTS = ["maxPages", "maxMinutes", "deepScan"];

function isCrawlSelected() {
  return document.querySelector('input[name="crawl-mode"]:checked').value === "multiple";
}

function clampInput(input) {
  const value = Math.round(Number(input.value));
  const min = Number(input.min), max = Number(input.max);
  return Number.isFinite(value) ? Math.min(max, Math.max(min, value)) : Number(input.defaultValue);
}

function scanOptions(crawl) {
  return {
    deep: el("deepScan").checked,
    max_pages: crawl ? clampInput(el("maxPages")) : null,
    max_minutes: crawl ? clampInput(el("maxMinutes")) : null
  };
}

function saveOptions() {
  try {
    OPTION_INPUTS.forEach(id => {
      const input = el(id);
      localStorage.setItem("webaudit." + id, input.type === "checkbox" ? String(input.checked) : input.value);
    });
  } catch (error) { /* Sin almacenamiento local: no se recuerdan */ }
}

function restoreOptions() {
  try {
    OPTION_INPUTS.forEach(id => {
      const saved = localStorage.getItem("webaudit." + id);
      if (saved === null) return;
      if (el(id).type === "checkbox") el(id).checked = saved === "true";
      else el(id).value = saved;
    });
  } catch (error) { /* Valores por defecto */ }
}

function updateCrawlLimits() {
  el("crawlLimits").hidden = !isCrawlSelected();
}

OPTION_INPUTS.forEach(id => el(id).addEventListener("change", () => {
  if (el(id).type === "number") el(id).value = clampInput(el(id));
  saveOptions();
}));
document.querySelectorAll('input[name="crawl-mode"]').forEach(input => {
  input.addEventListener("change", updateCrawlLimits);
});
restoreOptions();
updateCrawlLimits();

// --- Análisis ---------------------------------------------------------------------

// El análisis se ejecuta como un trabajo en el servidor: se crea, se consulta
// su progreso cada POLL_INTERVAL_MS y se puede cancelar.

let currentJobId = null;

async function apiRequest(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) {
    const detail = data.detail;
    const message = Array.isArray(detail)
      ? detail.map(item => item.msg || item).join(" ")
      : (detail || t().failed);
    throw new Error(message);
  }
  return data;
}

const sleep = ms => new Promise(resolve => window.setTimeout(resolve, ms));

async function runScanJob(target, crawl, options) {
  const { id } = await apiRequest("/scan/jobs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, crawl, ...options })
  });
  currentJobId = id;

  while (true) {
    const job = await apiRequest("/scan/jobs/" + id);
    renderProgress(job, crawl);
    if (job.state !== "running") return job;
    await sleep(POLL_INTERVAL_MS);
  }
}

function formatText(template, values) {
  return template.replace(/\{(\w+)\}/g, (_, key) => values[key]);
}

function formatElapsed(seconds) {
  const whole = Math.floor(seconds);
  return Math.floor(whole / 60) + ":" + String(whole % 60).padStart(2, "0");
}

function renderProgress(job, crawl) {
  const texts = t();
  const progress = job.progress || {};
  const done = progress.pages_scanned || 0;
  const fill = el("progressFill");

  let label = texts.progressStarting;
  let ratio = null;  // null = barra indeterminada
  if (job.cancel_requested) {
    label = texts.cancelling;
  } else if (crawl && progress.page_limit) {
    // Total estimado: lo analizado, lo que está en curso y lo pendiente en cola.
    const total = Math.min(
      progress.page_limit,
      done + (progress.current_page ? 1 : 0) + (progress.queued || 0)
    );
    label = formatText(texts.progressPages, { done, total: Math.max(total, 1) });
    ratio = done / Math.max(total, 1);
  } else if (progress.current_page) {
    label = texts.progressSingle;
  }
  if (job.state !== "running") {
    label = texts.progressFinishing;
    ratio = 1;
  }

  el("progressText").textContent = label;
  el("progressMeta").textContent =
    formatText(texts.progressFindings, { count: progress.findings || 0 }) +
    " · " + formatElapsed(job.elapsed_seconds || 0);
  el("progressCurrent").textContent = progress.current_page || "";
  if (progress.findings !== undefined) el("findingsValue").textContent = progress.findings;
  fill.classList.toggle("indeterminate", ratio === null);
  fill.style.width = ratio === null ? "" : Math.round(ratio * 100) + "%";
}

function setScanning(scanning) {
  el("scanButton").hidden = scanning;
  el("cancelButton").hidden = !scanning;
  el("cancelButton").disabled = false;
  el("cancelButton").textContent = t().cancelButton;
  el("target").disabled = scanning;
  document.querySelectorAll('input[name="crawl-mode"], .scan-options input').forEach(input => {
    input.disabled = scanning;
  });
  el("progressPanel").hidden = !scanning;
}

el("cancelButton").addEventListener("click", async () => {
  if (!currentJobId) return;
  el("cancelButton").disabled = true;
  el("cancelButton").textContent = t().cancelling;
  try {
    await apiRequest("/scan/jobs/" + currentJobId, { method: "DELETE" });
  } catch (error) {
    el("cancelButton").disabled = false;
  }
});

el("scanForm").addEventListener("submit", async event => {
  event.preventDefault();

  const target = el("target").value.trim();
  const crawl = isCrawlSelected();
  const options = scanOptions(crawl);

  resetResults();
  el("progressFill").style.width = "";
  el("progressCurrent").textContent = "";
  renderProgress({ state: "running", progress: {} }, crawl);
  setScanning(true);

  try {
    const job = await runScanJob(target, crawl, options);
    const saved = job.history_entry;
    lastScan = job.state === "error"
      ? { error: job.error || t().failed }
      : {
          state: job.state,
          result: job.result,
          finishedAt: saved ? saved.finished_at : new Date().toISOString(),
          historyId: saved ? saved.id : null
        };
    if (saved) document.dispatchEvent(new Event("historychange"));
  } catch (error) {
    lastScan = { error: error.message || t().failed };
  } finally {
    renderScan(lastScan);
    currentJobId = null;
    setScanning(false);
  }
});

applyTranslations();
