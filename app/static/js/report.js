// Informe exportable (HTML y PDF) de un análisis, en el idioma actual.
// Usa t(), lang, localize() y severityLabel() de app.js.

const REPORT_SEVERITY_ORDER = ["high", "medium", "low", "info"];

const REPORT_CSS = `
  .report-doc { color: #172033; background: #fff; font: 13px/1.5 "Segoe UI", Arial, sans-serif; }
  .report-doc * { box-sizing: border-box; }
  .report-doc .r-report { max-width: 900px; margin: 0 auto; padding: 32px; }
  .report-doc .r-brand { color: #0f9b6c; font-weight: 800; letter-spacing: 0.5px; }
  .report-doc h1 { margin: 6px 0 4px; font-size: 26px; }
  .report-doc h2 { margin: 28px 0 10px; padding-bottom: 6px; border-bottom: 2px solid #e3e8f0; font-size: 18px; }
  .report-doc h3 { margin: 18px 0 8px; font-size: 14px; color: #44516a; }
  .report-doc p { margin: 4px 0; color: inherit; line-height: 1.5; }
  .report-doc .r-target { margin: 0 0 18px; color: #44516a; word-break: break-all; }
  .report-doc table { width: 100%; border-collapse: collapse; }
  .report-doc .r-meta { margin-bottom: 18px; }
  .report-doc .r-meta th { width: 190px; text-align: left; color: #5d6b84; font-weight: 600; }
  .report-doc .r-meta th, .report-doc .r-meta td { padding: 5px 0; border-bottom: 1px solid #eef1f6; vertical-align: top; }
  .report-doc .r-counts { display: flex; gap: 10px; }
  .report-doc .r-count { flex: 1; padding: 12px; border: 1px solid #e3e8f0; border-radius: 8px; }
  .report-doc .r-count strong { display: block; font-size: 22px; }
  .report-doc .r-finding { margin: 0 0 10px; padding: 12px 14px; border: 1px solid #e3e8f0; border-left-width: 4px; border-radius: 6px; break-inside: avoid; }
  .report-doc .r-label { color: #5d6b84; font-weight: 600; }
  .report-doc .r-finding-title { font-weight: 700; }
  .report-doc .r-badge { display: inline-block; margin-right: 8px; padding: 1px 8px; border-radius: 999px; font-size: 10px; font-weight: 800; text-transform: uppercase; }
  .report-doc .r-sev-high { border-left-color: #d64545; } .report-doc .r-badge.r-sev-high { background: #fde8e8; color: #b42318; }
  .report-doc .r-sev-medium { border-left-color: #d99a12; } .report-doc .r-badge.r-sev-medium { background: #fdf3dc; color: #9a6400; }
  .report-doc .r-sev-low { border-left-color: #2f80c4; } .report-doc .r-badge.r-sev-low { background: #e3f0fb; color: #1b5e96; }
  .report-doc .r-sev-info { border-left-color: #8a96aa; } .report-doc .r-badge.r-sev-info { background: #eef1f6; color: #4a5568; }
  .report-doc .r-checks { margin-bottom: 8px; }
  .report-doc .r-checks th, .report-doc .r-checks td { padding: 6px 8px; border-bottom: 1px solid #eef1f6; text-align: left; vertical-align: top; }
  .report-doc .r-checks th { background: #f6f8fb; color: #5d6b84; font-size: 12px; }
  .report-doc .r-checks tr { break-inside: avoid; }
  .report-doc .r-status-pass { color: #0f8a5f; } .report-doc .r-status-warning { color: #9a6400; }
  .report-doc .r-status-fail { color: #b42318; } .report-doc .r-status-unknown, .report-doc .r-status-info { color: #5d6b84; }
  .report-doc .r-details, .report-doc .r-page { color: #5d6b84; word-break: break-word; }
  .report-doc .r-page { font-size: 12px; word-break: break-all; }
  .report-doc a { color: #1b5e96; }
  .report-doc .r-footer { margin-top: 28px; padding-top: 12px; border-top: 1px solid #e3e8f0; color: #5d6b84; font-size: 11px; }
  @page { margin: 14mm; }
`;

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

function reportDate(scan) {
  const date = scan.finishedAt ? new Date(scan.finishedAt) : new Date();
  return date.toLocaleString(lang === "es" ? "es-ES" : "en-GB");
}

function reportFilename(scan, extension) {
  let host = "sitio";
  try { host = new URL(scan.result.target).hostname; } catch (error) { /* URL no válida */ }
  const date = scan.finishedAt ? new Date(scan.finishedAt) : new Date();
  const pad = number => String(number).padStart(2, "0");
  const stamp = `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}` +
    `-${pad(date.getHours())}${pad(date.getMinutes())}`;  // Hora local
  return `webaudit-${host}-${stamp}.${extension}`;
}

function reportFinding(finding, showPage) {
  const texts = t();
  const severity = esc(finding.severity);
  const reference = finding.owasp_reference
    ? ` · <a href="${esc(finding.owasp_reference)}">${esc(texts.owaspGuide)}</a>`
    : "";
  return `
    <div class="r-finding r-sev-${severity}">
      <div><span class="r-badge r-sev-${severity}">${esc(severityLabel(finding.severity))}</span>
        <span class="r-finding-title">${esc(localize(finding.title, finding, "title"))}</span></div>
      ${showPage && finding.page ? `<p class="r-page">${esc(finding.page)}</p>` : ""}
      <p><span class="r-label">${esc(texts.evidence)}:</span> ${esc(localize(finding.evidence, finding, "evidence"))}</p>
      <p><span class="r-label">${esc(texts.recommendation)}:</span> ${esc(localize(finding.recommendation, finding, "recommendation"))}</p>
      ${finding.owasp_category ? `<p><span class="r-label">${esc(texts.owaspCategory)}:</span> ${esc(localize(finding.owasp_category))}${reference}</p>` : ""}
    </div>`;
}

function reportChecks(checks, showPage) {
  const texts = t();
  const byCategory = groupBy(checks, check => check.category || "configuration");
  let html = "";
  byCategory.forEach((categoryChecks, category) => {
    const rows = categoryChecks.map(check => {
      const status = texts.statuses[check.status] ? check.status : "unknown";
      return `<tr>
        <td class="r-status-${status}">${esc(texts.statuses[status])}</td>
        <td>${esc(localize(check.title, check, "title") || check.id)}
          ${showPage && check.page ? `<div class="r-page">${esc(check.page)}</div>` : ""}</td>
        <td class="r-details">${esc(localize(check.details, check, "details"))}</td>
      </tr>`;
    }).join("");
    html += `<h3>${esc(texts.categories[category] || category)}</h3>
      <table class="r-checks"><thead><tr>
        <th>${esc(texts.reportStatus)}</th><th>${esc(texts.reportCheck)}</th><th>${esc(texts.reportDetails)}</th>
      </tr></thead><tbody>${rows}</tbody></table>`;
  });
  return html;
}

/** Cuerpo del informe (sin <html>), para el PDF y para el documento HTML. */
function buildReportBody(scan) {
  const texts = t();
  const result = scan.result;
  const summary = result.summary || {};
  const findings = [...(result.findings || [])].sort(
    (a, b) => REPORT_SEVERITY_ORDER.indexOf(a.severity) - REPORT_SEVERITY_ORDER.indexOf(b.severity)
  );
  const crawl = (result.page_limit || 1) > 1;
  const state = scan.state === "cancelled" ? texts.cancelled : texts.done;

  const counts = REPORT_SEVERITY_ORDER.map(severity => `
    <div class="r-count"><span>${esc(severityLabel(severity))}</span><strong>${summary[severity] ?? 0}</strong></div>`
  ).join("");

  return `
    <div class="report-doc"><div class="r-report">
      <div class="r-brand">WebAudit Sec</div>
      <h1>${esc(texts.reportTitle)}</h1>
      <p class="r-target">${esc(result.target)}</p>
      <table class="r-meta">
        <tr><th>${esc(texts.reportDate)}</th><td>${esc(reportDate(scan))}</td></tr>
        <tr><th>${esc(texts.crawlMode)}</th><td>${esc(crawl ? texts.linkedPages : texts.singlePage)}</td></tr>
        <tr><th>${esc(texts.reportPages)}</th><td>${esc(result.pages_scanned ?? 1)}</td></tr>
        <tr><th>${esc(texts.statusLabel)}</th><td>${esc(state)} · ${esc(crawlTitle(result))}</td></tr>
        <tr><th>${esc(texts.httpLabel)}</th><td>${esc(result.http_status)}</td></tr>
        <tr><th>${esc(texts.findingsLabel)}</th><td>${esc(result.findings_count ?? findings.length)}</td></tr>
      </table>
      <div class="r-counts">${counts}</div>

      <h2>${esc(texts.findingsLabel)}</h2>
      ${findings.length ? findings.map(finding => reportFinding(finding, crawl)).join("") : `<p>${esc(texts.none)}</p>`}

      <h2>${esc(texts.checksTitle)}</h2>
      ${reportChecks(result.checks || [], crawl)}

      <div class="r-footer">
        <p>${esc(texts.severityDisclaimer)}</p>
        <p>${esc(formatText(texts.reportGenerated, { date: new Date().toLocaleString(lang === "es" ? "es-ES" : "en-GB") }))}</p>
      </div>
    </div></div>`;
}

/** Documento HTML independiente (estilos incluidos) para guardar o compartir. */
function buildReportDocument(scan) {
  return `<!DOCTYPE html>
<html lang="${lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(t().reportTitle)} · ${esc(scan.result.target)}</title>
<style>${REPORT_CSS}</style>
</head>
<body style="margin:0">${buildReportBody(scan)}</body>
</html>`;
}

// --- Exportar ----------------------------------------------------------------------
// En la app de escritorio se guarda con el diálogo de Windows (DesktopApi en
// desktop.py); en un navegador, HTML se descarga y PDF usa el diálogo de imprimir.

function isDesktop() {
  return document.documentElement.classList.contains("desktop");
}

/** Para el PDF, el informe se imprime desde esta página: necesita sus estilos. */
function ensureReportStyles() {
  if (document.getElementById("reportStyles")) return;
  const style = document.createElement("style");
  style.id = "reportStyles";
  style.textContent = REPORT_CSS;
  document.head.appendChild(style);
}

function downloadFile(filename, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function exportReport(format) {
  if (!lastScan || !lastScan.result) return;
  const texts = t();
  const status = el("exportStatus");
  const filename = reportFilename(lastScan, format);
  const buttons = [el("exportHtml"), el("exportPdf")];
  buttons.forEach(button => { button.disabled = true; });
  status.textContent = texts.exportPreparing;

  try {
    let savedPath = null;
    if (format === "html") {
      const html = buildReportDocument(lastScan);
      if (isDesktop()) {
        savedPath = await window.pywebview.api.save_html(filename, html);
      } else {
        downloadFile(filename, html, "text/html");
        savedPath = filename;
      }
    } else {
      ensureReportStyles();
      el("printReport").innerHTML = buildReportBody(lastScan);
      if (isDesktop()) {
        savedPath = await window.pywebview.api.save_pdf(filename);
      } else {
        window.print();  // "Guardar como PDF" en el diálogo del navegador
      }
    }
    status.textContent = savedPath ? formatText(texts.exportSaved, { path: savedPath }) : "";
  } catch (error) {
    status.textContent = texts.exportFailed;
  } finally {
    buttons.forEach(button => { button.disabled = false; });
  }
}

el("exportHtml").addEventListener("click", () => exportReport("html"));
el("exportPdf").addEventListener("click", () => exportReport("pdf"));
