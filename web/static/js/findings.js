// Vista de hallazgos: filtros (gravedad y texto), agrupación (por hallazgo o
// por página) y comparación con el análisis anterior del mismo sitio.
// Usa el(), t(), lang, localize(), addText(), addBadge(), addGroup(), groupBy(),
// severityLabel(), formatText(), crawlTitle(), apiRequest() y lastScan de app.js.

const SEVERITY_ORDER = ["high", "medium", "low", "info"];

const findingsView = {
  severities: new Set(SEVERITY_ORDER),  // Gravedades visibles
  query: "",
  groupBy: "finding"
};

/** Identifica un hallazgo para compararlo entre análisis. */
function findingKey(finding, target) {
  return [finding.id, finding.title, finding.page || target].join("|");
}

/** Agrupa hallazgos iguales en distintas páginas (mismo id y título). */
function groupFindings(findings) {
  const groups = [...groupBy(findings, finding => finding.id + "|" + finding.title).values()];
  return groups.sort((a, b) =>
    SEVERITY_ORDER.indexOf(a[0].severity) - SEVERITY_ORDER.indexOf(b[0].severity) ||
    b.length - a.length
  );
}

function matchesQuery(finding, query) {
  if (!query) return true;
  const text = [
    localize(finding.title, finding, "title"),
    localize(finding.evidence, finding, "evidence"),
    finding.page || "",
    finding.id
  ].join(" ").toLowerCase();
  return text.includes(query);
}

function visibleFindings(findings) {
  const query = findingsView.query.trim().toLowerCase();
  return findings.filter(finding =>
    findingsView.severities.has(finding.severity) && matchesQuery(finding, query)
  );
}

// --- Barra de filtros -----------------------------------------------------------

function renderToolbar(findings) {
  const texts = t();
  const filters = el("severityFilters");
  filters.replaceChildren();
  SEVERITY_ORDER.forEach(severity => {
    const count = findings.filter(finding => finding.severity === severity).length;
    const button = addText(filters, "button", severityLabel(severity) + " " + count, "badge sev-" + severity);
    button.type = "button";
    button.classList.toggle("off", !findingsView.severities.has(severity));
    button.setAttribute("aria-pressed", String(findingsView.severities.has(severity)));
    button.addEventListener("click", () => {
      if (findingsView.severities.has(severity)) findingsView.severities.delete(severity);
      else findingsView.severities.add(severity);
      rerenderFindings();
    });
  });
  el("findingsSearch").placeholder = texts.findingsSearch;
  el("findingsToolbar").hidden = !findings.length;
}

function rerenderFindings() {
  if (lastScan && lastScan.result) renderFindings(lastScan.result);
}

el("findingsSearch").addEventListener("input", event => {
  findingsView.query = event.target.value;
  rerenderFindings();
});
el("groupBy").addEventListener("change", event => {
  findingsView.groupBy = event.target.value;
  rerenderFindings();
});

// --- Tarjetas de hallazgo ---------------------------------------------------------

function addNewBadge(parent) {
  addText(parent, "span", t().newFinding, "badge new-finding");
}

function addFindingBody(body, finding) {
  const texts = t();
  addText(body, "p", texts.recommendation + ": " + localize(finding.recommendation, finding, "recommendation"));
  if (finding.owasp_category) {
    addText(body, "p", texts.owaspCategory + ": " + localize(finding.owasp_category));
  }
  if (finding.owasp_reference) {
    const link = addText(body, "a", texts.owaspGuide);
    link.href = finding.owasp_reference;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
  }
}

function findingCard(parent, finding, meta, isNew) {
  const card = document.createElement("details");
  card.className = "finding";
  const summary = document.createElement("summary");
  const head = document.createElement("span");
  head.className = "finding-head";
  addBadge(head, finding.severity);
  if (isNew) addNewBadge(head);
  summary.appendChild(head);
  addText(summary, "span", localize(finding.title, finding, "title"), "finding-title");
  if (meta) addText(summary, "span", meta, "group-meta");
  card.appendChild(summary);

  const body = document.createElement("div");
  body.className = "finding-body";
  card.appendChild(body);
  parent.appendChild(card);
  return body;
}

/** Un hallazgo (en la vista por página). */
function renderFinding(parent, finding, isNew = false) {
  const texts = t();
  const body = findingCard(parent, finding, "", isNew);
  addText(body, "p", texts.evidence + ": " + localize(finding.evidence, finding, "evidence"));
  addFindingBody(body, finding);
}

/** Un hallazgo agrupado: una tarjeta con las páginas afectadas. */
function renderFindingGroup(parent, group, target, newKeys, multiPage) {
  const texts = t();
  const first = group[0];
  const isNew = group.some(finding => newKeys.has(findingKey(finding, target)));
  const meta = multiPage ? formatText(texts.affectedPages, { count: group.length }) : "";
  const body = findingCard(parent, first, meta, isNew);

  const evidences = new Set(group.map(finding => localize(finding.evidence, finding, "evidence")));
  if (evidences.size === 1) {
    addText(body, "p", texts.evidence + ": " + [...evidences][0]);
  }
  if (multiPage) {
    const list = addText(body, "ul", "", "affected-pages");
    group.forEach(finding => {
      const item = addText(list, "li", finding.page || target, "page-url");
      if (evidences.size > 1) addText(item, "span", " · " + localize(finding.evidence, finding, "evidence"), "page-evidence");
    });
  }
  addFindingBody(body, first);
}

// --- Comparación con el análisis anterior ------------------------------------------

/** Carga (una vez) el análisis anterior del mismo sitio y repinta la comparación. */
async function loadPreviousScan(scan) {
  if (!scan || !scan.historyId || scan.previous !== undefined) return;
  scan.previous = null;
  try {
    const entry = await apiRequest("/history/" + scan.historyId + "/previous");
    scan.previous = { finishedAt: entry.finished_at, findings: entry.result.findings || [] };
  } catch (error) {
    return;  // Primer análisis de este sitio: no hay con qué comparar
  }
  if (lastScan === scan) rerenderFindings();
}

function comparison(data, previous) {
  const currentKeys = new Set(data.findings.map(finding => findingKey(finding, data.target)));
  const previousKeys = new Set(previous.findings.map(finding => findingKey(finding, data.target)));
  return {
    newKeys: new Set([...currentKeys].filter(key => !previousKeys.has(key))),
    fixed: previous.findings.filter(finding => !currentKeys.has(findingKey(finding, data.target))),
    kept: [...currentKeys].filter(key => previousKeys.has(key)).length
  };
}

function renderComparison(diff, previous, target) {
  const texts = t();
  const box = el("comparison");
  box.replaceChildren();
  if (!diff) return;

  const banner = addText(box, "div", "", "comparison");
  addText(banner, "strong", formatText(texts.compareTitle, {
    date: new Date(previous.finishedAt).toLocaleString(lang === "es" ? "es-ES" : "en-GB", {
      dateStyle: "medium", timeStyle: "short"
    })
  }));
  const counts = addText(banner, "div", "", "comparison-counts");
  addText(counts, "span", formatText(texts.compareNew, { count: diff.newKeys.size }), "compare-new");
  addText(counts, "span", formatText(texts.compareFixed, { count: diff.fixed.length }), "compare-fixed");
  addText(counts, "span", formatText(texts.compareKept, { count: diff.kept }), "compare-kept");

  if (diff.fixed.length) {
    const details = document.createElement("details");
    details.className = "fixed-findings";
    addText(details, "summary", texts.compareFixedList);
    groupFindings(diff.fixed).forEach(group => {
      const item = addText(details, "p", "");
      addBadge(item, group[0].severity);
      addText(item, "span", localize(group[0].title, group[0], "title"));
      if (group.length > 1 || group[0].page !== target) {
        addText(item, "span", " · " + formatText(texts.affectedPages, { count: group.length }), "group-meta");
      }
    });
    banner.appendChild(details);
  }
}

// --- Lista de hallazgos ---------------------------------------------------------------

function renderFindings(data) {
  const texts = t();
  const results = el("results");
  results.replaceChildren();
  const findings = data.findings || [];
  const previous = lastScan && lastScan.previous;
  const diff = previous ? comparison(data, previous) : null;
  const newKeys = diff ? diff.newKeys : new Set();

  renderToolbar(findings);
  renderComparison(diff, previous, data.target);

  if (data.http_status >= 300 && data.http_status < 400) addText(results, "p", texts.redirect);
  addText(results, "p", data.target, "url-text");
  addText(results, "h3", crawlTitle(data));
  if (Array.isArray(data.failed_pages) && data.failed_pages.length) {
    const failedList = addText(results, "ul", "", "url-text");
    data.failed_pages.forEach(page => addText(failedList, "li", page, "page-url"));
  }
  if (!findings.length) {
    addText(results, "p", texts.none);
    return;
  }

  const visible = visibleFindings(findings);
  if (!visible.length) {
    addText(results, "p", texts.noMatchingFindings);
    return;
  }
  if (visible.length !== findings.length) {
    addText(results, "p", formatText(texts.showingFindings, { shown: visible.length, total: findings.length }), "filter-note");
  }

  const multiPage = (data.scanned_pages || []).length > 1;
  if (findingsView.groupBy === "page") {
    const byPage = groupBy(visible, finding => finding.page || data.target);
    byPage.forEach((pageFindings, page) => {
      const content = addGroup(results, page, pageFindings.length + " " + texts.findingsCount, "page-url");
      pageFindings.forEach(finding =>
        renderFinding(content, finding, newKeys.has(findingKey(finding, data.target)))
      );
    });
  } else {
    groupFindings(visible).forEach(group =>
      renderFindingGroup(results, group, data.target, newKeys, multiPage)
    );
  }

  loadPreviousScan(lastScan);
}

document.addEventListener("languagechange", () => {
  el("findingsSearch").placeholder = t().findingsSearch;
});
