// Comportamiento de app de escritorio: barra de título propia y sin gestos de navegador.
// Los controles de ventana solo se activan dentro de la app (pywebview); en un
// navegador normal la barra se ve, pero sin botones de ventana.

(function () {
  const root = document.documentElement;
  let api = null;

  function setMaximized(maximized) {
    root.classList.toggle("maximized", Boolean(maximized));
  }

  async function startDrag(edge) {
    setMaximized(await api.start_drag(edge));
  }

  async function toggleMaximize() {
    setMaximized(await api.toggle_maximize());
  }

  function isInteractive(target) {
    return Boolean(target.closest("button, input, a, select, textarea"));
  }

  window.addEventListener("pywebviewready", () => {
    api = window.pywebview.api;
    root.classList.add("desktop");

    // El arrastre empieza al mover el ratón unos píxeles, para no tapar el doble clic.
    const titlebar = document.getElementById("titlebar");
    let pressedAt = null;
    titlebar.addEventListener("mousedown", event => {
      if (event.button === 0 && !isInteractive(event.target)) {
        pressedAt = { x: event.screenX, y: event.screenY };
      }
    });
    window.addEventListener("mousemove", event => {
      if (!pressedAt || !(event.buttons & 1)) {
        pressedAt = null;
        return;
      }
      if (Math.abs(event.screenX - pressedAt.x) + Math.abs(event.screenY - pressedAt.y) > 3) {
        pressedAt = null;
        startDrag("move");
      }
    });
    window.addEventListener("mouseup", () => { pressedAt = null; });
    titlebar.addEventListener("dblclick", event => {
      if (!isInteractive(event.target)) toggleMaximize();
    });

    document.querySelectorAll(".resize-handles [data-edge]").forEach(handle => {
      handle.addEventListener("mousedown", event => {
        if (event.button === 0) startDrag(handle.dataset.edge);
      });
    });

    document.getElementById("windowMinimize").addEventListener("click", () => api.minimize());
    document.getElementById("windowMaximize").addEventListener("click", toggleMaximize);
    document.getElementById("windowClose").addEventListener("click", () => api.close());
  });

  // Sin menú contextual del navegador (salvo en campos de texto) ni atajos de página web.
  document.addEventListener("contextmenu", event => {
    if (!event.target.closest("input, textarea")) event.preventDefault();
  });

  document.addEventListener("keydown", event => {
    const key = event.key.toLowerCase();
    const reload = key === "f5" || (event.ctrlKey && key === "r");
    const browserShortcut = event.ctrlKey && ["p", "s", "u", "f", "g", "j"].includes(key);
    if (reload || browserShortcut) event.preventDefault();
  });
})();
