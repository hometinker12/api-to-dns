const providerSelect = document.getElementById("dns-provider-type");
const providerPanels = Array.from(document.querySelectorAll("[data-provider-panel]"));
const zoneForm = document.getElementById("zone-form");
const zoneTestBtn = document.getElementById("zone-test-btn");
const zoneTestResult = document.getElementById("zone-test-result");

const syncProviderPanels = () => {
  const selectedProvider = providerSelect?.value;
  providerPanels.forEach((panel) => {
    const active = panel.dataset.providerPanel === selectedProvider;
    panel.hidden = !active;
    panel.querySelectorAll("input, select, textarea").forEach((field) => {
      field.disabled = !active;
    });
  });
};
const showZoneTestResult = (kind, message) => {
  if (!zoneTestResult) return;
  zoneTestResult.hidden = false;
  zoneTestResult.className = "alert";
  zoneTestResult.classList.add(kind === "success" ? "success" : "error");
  zoneTestResult.textContent = message;
};

zoneTestBtn?.addEventListener("click", async () => {
  if (!zoneForm) return;
  const originalLabel = zoneTestBtn.textContent;
  zoneTestBtn.disabled = true;
  zoneTestBtn.textContent = "Testing Authentication…";
  if (zoneTestResult) zoneTestResult.hidden = true;
  try {
    const response = await fetch("/zones/test", {
      method: "POST",
      headers: { Accept: "application/json" },
      body: new FormData(zoneForm),
      credentials: "same-origin",
    });
    const payload = await response.json();
    if (payload.status === "success") {
      showZoneTestResult("success", "Authentication test successful. Found matching records.");
    } else if (payload.status === "not_found") {
      showZoneTestResult("success", payload.message || "Authentication test successful. No matching records found.");
    } else {
      showZoneTestResult("error", payload.message || "DNS test failed.");
    }
  } catch (_error) {
    showZoneTestResult("error", "DNS test failed.");
  } finally {
    zoneTestBtn.disabled = false;
    zoneTestBtn.textContent = originalLabel;
  }
});

providerSelect?.addEventListener("change", syncProviderPanels);
syncProviderPanels();
