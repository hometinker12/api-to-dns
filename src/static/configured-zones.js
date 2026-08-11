(() => {
  const dialog = document.getElementById("delete-zone-dialog");
  const form = document.getElementById("delete-zone-form");
  const name = document.getElementById("delete-zone-name");
  const apiKeys = document.getElementById("delete-zone-api-keys");
  const letsEncryptWarning = document.getElementById("delete-zone-le-warning");
  const apiKeyCountLabel = (count) => {
    const value = Number(count);
    return value === 1
      ? "1 API key is currently allowed to use this zone."
      : `${value} API keys are currently allowed to use this zone.`;
  };

  document.querySelectorAll("[data-open-delete-zone]").forEach((button) => {
    button.addEventListener("click", () => {
      const zoneId = button.dataset.zoneId;
      if (name) name.textContent = button.dataset.zoneName || "";
      if (apiKeys) apiKeys.textContent = apiKeyCountLabel(button.dataset.apiKeyCount ?? "0");
      if (letsEncryptWarning) letsEncryptWarning.hidden = button.dataset.leReferenced !== "true";
      if (form && zoneId) form.action = `/zones/${zoneId}/delete`;
      dialog?.showModal();
    });
  });
  document.getElementById("delete-zone-close")?.addEventListener("click", () => dialog?.close());
  document.getElementById("delete-zone-cancel")?.addEventListener("click", () => dialog?.close());
})();
