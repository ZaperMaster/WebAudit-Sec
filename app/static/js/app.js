// Lógica de la interfaz de WebAudit Sec.

const SCAN_TIMEOUT_MS = { single: 45000, crawl: 330000 };
const STAT_IDS = [
  "httpValue", "findingsValue",
  "checksPass", "checksWarning", "checksUnknown",
  "highValue", "mediumValue", "lowValue", "infoValue"
];

let lang = "es";
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

el("language").addEventListener("click", () => {
  lang = lang === "es" ? "en" : "es";
  applyTranslations();
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

function resetResults() {
  el("statusValue").textContent = t().scanning;
  STAT_IDS.forEach(id => { el(id).textContent = "—"; });
  el("results").replaceChildren();
  el("checksList").replaceChildren();
}

function renderSummary(data) {
  const summary = data.summary || {};
  el("statusValue").textContent = t().done;
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
      addText(item, "h3", check.title || check.id || texts.defaultCheckTitle);
      if (check.details) addText(item, "p", check.details);
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
  if (data.page_limit === 1) return texts.singlePageComplete;
  return data.crawl_complete ? texts.crawlComplete : texts.crawlIncomplete;
}

function renderFinding(parent, finding) {
  const texts = t();
  const card = document.createElement("details");
  card.className = "finding";

  const summary = document.createElement("summary");
  const head = document.createElement("span");
  head.className = "finding-head";
  addBadge(head, finding.severity);
  summary.appendChild(head);
  addText(summary, "span", finding.title, "finding-title");
  card.appendChild(summary);

  const body = document.createElement("div");
  body.className = "finding-body";
  addText(body, "p", texts.severity + ": " + severityLabel(finding.severity));
  addText(body, "p", texts.evidence + ": " + finding.evidence);
  addText(body, "p", texts.recommendation + ": " + finding.recommendation);
  if (finding.owasp_category) {
    addText(body, "p", texts.owaspCategory + ": " + finding.owasp_category);
  }
  if (finding.owasp_reference) {
    const link = addText(body, "a", texts.owaspGuide);
    link.href = finding.owasp_reference;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
  }
  card.appendChild(body);
  parent.appendChild(card);
}

function renderFindings(data) {
  const texts = t();
  const results = el("results");
  const findings = data.findings || [];

  if (data.http_status >= 300 && data.http_status < 400) {
    addText(results, "p", texts.redirect);
  }
  addText(results, "p", data.target, "url-text");
  addText(results, "h3", crawlTitle(data));

  if (Array.isArray(data.failed_pages) && data.failed_pages.length) {
    const failedList = addText(results, "ul", "", "url-text");
    data.failed_pages.forEach(page => addText(failedList, "li", page, "page-url"));
  }
  if (!findings.length) {
    addText(results, "p", texts.none);
  }

  const byPage = groupBy(
    findings,
    finding => finding.page || data.target,
    data.scanned_pages || [data.target]
  );
  byPage.forEach((pageFindings, page) => {
    const content = addGroup(
      results,
      page,
      pageFindings.length + " " + texts.findingsCount,
      "page-url"
    );
    if (!pageFindings.length) addText(content, "p", texts.none);
    pageFindings.forEach(finding => renderFinding(content, finding));
  });
}

// --- Análisis ---------------------------------------------------------------------

async function requestScan(target, crawl) {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(
    () => controller.abort(),
    crawl ? SCAN_TIMEOUT_MS.crawl : SCAN_TIMEOUT_MS.single
  );

  try {
    const response = await fetch("/scan/website", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, crawl }),
      signal: controller.signal
    });
    const data = await response.json();

    if (!response.ok) {
      const detail = data.detail;
      const message = Array.isArray(detail)
        ? detail.map(item => item.msg || item).join(" ")
        : (detail || t().failed);
      throw new Error(message);
    }
    return data;
  } finally {
    window.clearTimeout(timeoutId);
  }
}

el("scanForm").addEventListener("submit", async event => {
  event.preventDefault();

  const target = el("target").value.trim();
  const crawl = document.querySelector('input[name="crawl-mode"]:checked').value === "multiple";

  resetResults();
  el("scanButton").disabled = true;

  try {
    const data = await requestScan(target, crawl);
    renderSummary(data);
    renderChecks(data.checks || []);
    renderFindings(data);
  } catch (error) {
    el("statusValue").textContent = t().error;
    const message = error.name === "AbortError" ? t().timeout : (error.message || t().failed);
    addText(el("results"), "p", message);
  } finally {
    el("scanButton").disabled = false;
  }
});

applyTranslations();
