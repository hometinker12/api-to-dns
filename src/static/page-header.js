(() => {
  const key = "api-to-dns-theme";
  const toggle = document.getElementById("theme-toggle");
  if (!toggle) {
    return;
  }

  const currentTheme = () =>
    document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";

  const applyTheme = (theme) => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem(key, theme);
    const next = theme === "dark" ? "light" : "dark";
    toggle.setAttribute("aria-label", `Switch to ${next} mode`);
    toggle.setAttribute("title", `Switch to ${next} mode`);
  };

  applyTheme(currentTheme());
  toggle.addEventListener("click", () => {
    applyTheme(currentTheme() === "dark" ? "light" : "dark");
  });
})();

(() => {
  const restartWaitMs = 20000;
  const restartTickMs = 200;
  const confirmDialog = document.getElementById("restart-app-dialog");
  const waitDialog = document.getElementById("restart-wait-dialog");
  const restartForm = document.getElementById("restart-app-form");
  const restartSubmit = document.getElementById("restart-app-submit");
  const afterUrlEl = document.getElementById("restart-after-url");
  const restartBtn = document.getElementById("restart-app-btn");
  const waitStatus = document.getElementById("restart-wait-status");
  const waitProgress = document.getElementById("restart-wait-progress");
  const waitTarget = document.getElementById("restart-wait-target");
  let restartTimer = null;
  let restartRedirecting = false;

  const resolveAfterRestartUrl = () =>
    afterUrlEl?.textContent?.trim() ||
    restartBtn?.dataset.afterUrl?.trim() ||
    waitDialog?.dataset.afterRestartUrl?.trim() ||
    "";
  const isAbsoluteAccessUrl = (url) => /^https?:\/\//i.test(url);
  const stopRestartTimer = () => {
    if (restartTimer !== null) {
      window.clearInterval(restartTimer);
      restartTimer = null;
    }
  };

  const beginRestartWait = (initialAfterRestartUrl) => {
    if (!isAbsoluteAccessUrl(initialAfterRestartUrl) || restartRedirecting) {
      return;
    }
    restartRedirecting = true;
    stopRestartTimer();
    confirmDialog?.close();
    if (restartSubmit) restartSubmit.disabled = true;
    if (waitProgress) waitProgress.value = 0;

    let afterRestartUrl = initialAfterRestartUrl;
    const updateAfterRestartUrl = (url) => {
      if (!isAbsoluteAccessUrl(url)) return;
      afterRestartUrl = url;
      if (waitTarget) waitTarget.textContent = afterRestartUrl;
      if (waitDialog) waitDialog.dataset.afterRestartUrl = afterRestartUrl;
    };
    updateAfterRestartUrl(afterRestartUrl);
    if (waitStatus) waitStatus.textContent = "Restarting application. Please wait…";
    waitDialog?.showModal();
    const startedAt = Date.now();

    fetch("/system/restart", {
      method: "POST",
      credentials: "same-origin",
      headers: { accept: "application/json" },
    })
      .then((response) => (response.ok ? response.json() : null))
      .then((payload) => {
        if (payload?.after_restart_url) updateAfterRestartUrl(payload.after_restart_url);
      })
      .catch(() => {});

    restartTimer = window.setInterval(() => {
      const elapsed = Date.now() - startedAt;
      const percent = Math.min(100, Math.round((elapsed / restartWaitMs) * 100));
      if (waitProgress) waitProgress.value = percent;
      const remainingSeconds = Math.max(0, Math.ceil((restartWaitMs - elapsed) / 1000));
      if (waitStatus) waitStatus.textContent = `Restarting application… (${remainingSeconds}s remaining)`;
      if (elapsed >= restartWaitMs) {
        stopRestartTimer();
        if (waitProgress) waitProgress.value = 100;
        window.location.replace(afterRestartUrl);
      }
    }, restartTickMs);
  };

  restartBtn?.addEventListener("click", () => confirmDialog?.showModal());
  document.getElementById("restart-app-close")?.addEventListener("click", () => confirmDialog?.close());
  document.getElementById("restart-app-cancel")?.addEventListener("click", () => confirmDialog?.close());
  restartForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    const afterRestartUrl = resolveAfterRestartUrl();
    if (!isAbsoluteAccessUrl(afterRestartUrl)) {
      window.alert("The new access URL after restart is not available.");
      return;
    }
    beginRestartWait(afterRestartUrl);
  });
  waitDialog?.addEventListener("cancel", (event) => {
    if (restartRedirecting) event.preventDefault();
  });
})();
