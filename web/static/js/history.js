// Panel de historial: lista los análisis guardados, los abre y los elimina.
// Usa el(), t(), lang, apiRequest(), renderScan() y lastScan de app.js.

(function () {
  const panel = el("historyPanel");
  let entries = [];

  function formatDate(iso) {
    return new Date(iso).toLocaleString(lang === "es" ? "es-ES" : "en-GB", {
      dateStyle: "medium", timeStyle: "short"
    });
  }

  function severityChips(summary) {
    const chips = document.createElement("div");
    chips.className = "history-chips";
    ["high", "medium", "low", "info"].forEach(severity => {
      const count = (summary || {})[severity] || 0;
      const chip = addText(chips, "span", severityLabel(severity) + " " + count, "badge sev-" + severity);
      if (!count) chip.classList.add("empty");
    });
    return chips;
  }

  function renderHistory() {
    const texts = t();
    const list = el("historyList");
    list.replaceChildren();
    if (!entries.length) {
      addText(list, "p", texts.historyEmpty, "history-empty");
      return;
    }

    entries.forEach(entry => {
      const item = document.createElement("article");
      item.className = "history-item";
      if (lastScan && lastScan.historyId === entry.id) item.classList.add("current");

      addText(item, "div", entry.target, "history-target");
      const scope = entry.crawl
        ? formatText(texts.historyPages, { count: entry.pages_scanned ?? 1 })
        : texts.singlePage;
      const state = entry.state === "cancelled" ? " · " + texts.cancelled : "";
      addText(item, "div", formatDate(entry.finished_at) + " · " + scope + state, "history-meta");
      item.appendChild(severityChips(entry.summary));

      const actions = document.createElement("div");
      actions.className = "history-actions";
      const open = addText(actions, "button", texts.historyOpen);
      open.type = "button";
      open.addEventListener("click", () => openEntry(entry.id));

      // Borrar pide confirmación con un segundo clic (sin diálogos del navegador).
      const remove = addText(actions, "button", texts.historyDelete, "danger");
      remove.type = "button";
      remove.addEventListener("click", () => {
        if (remove.dataset.confirm) {
          deleteEntry(entry.id);
        } else {
          remove.dataset.confirm = "1";
          remove.textContent = t().historyConfirmDelete;
          window.setTimeout(() => {
            delete remove.dataset.confirm;
            remove.textContent = t().historyDelete;
          }, 3000);
        }
      });
      item.appendChild(actions);
      list.appendChild(item);
    });
  }

  async function loadHistory() {
    try {
      entries = await apiRequest("/history");
    } catch (error) {
      entries = [];
    }
    renderHistory();
  }

  async function openEntry(id) {
    const entry = await apiRequest("/history/" + id);
    lastScan = {
      state: entry.state,
      result: entry.result,
      finishedAt: entry.finished_at,
      historyId: entry.id
    };
    el("target").value = entry.target;
    document.querySelector(
      `input[name="crawl-mode"][value="${entry.crawl ? "multiple" : "single"}"]`
    ).checked = true;
    renderScan(lastScan);
    setPanelOpen(false);
    el("statusValue").scrollIntoView({ behavior: "smooth", block: "center" });
  }

  async function deleteEntry(id) {
    try {
      await apiRequest("/history/" + id, { method: "DELETE" });
    } finally {
      if (lastScan && lastScan.historyId === id) lastScan.historyId = null;
      loadHistory();
    }
  }

  function setPanelOpen(open) {
    panel.hidden = !open;
    el("historyButton").classList.toggle("active", open);
    if (open) loadHistory();
  }

  el("historyButton").addEventListener("click", () => setPanelOpen(panel.hidden));
  el("historyClose").addEventListener("click", () => setPanelOpen(false));
  document.addEventListener("keydown", event => {
    if (event.key === "Escape" && !panel.hidden) setPanelOpen(false);
  });

  document.addEventListener("historychange", () => { if (!panel.hidden) loadHistory(); });
  document.addEventListener("languagechange", () => {
    el("historyClose").setAttribute("aria-label", t().historyCloseLabel);
    if (!panel.hidden) renderHistory();
  });
  el("historyClose").setAttribute("aria-label", t().historyCloseLabel);
})();
