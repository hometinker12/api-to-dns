const createDialog = document.getElementById("create-key-dialog");
const openCreateKey = document.getElementById("open-create-key");
const closeCreateKey = document.getElementById("close-create-key");
const cancelCreateKey = document.getElementById("cancel-create-key");

openCreateKey?.addEventListener("click", () => createDialog?.showModal());
closeCreateKey?.addEventListener("click", () => createDialog?.close());
cancelCreateKey?.addEventListener("click", () => createDialog?.close());
if (createDialog?.dataset.autoOpen === "true") {
  createDialog.showModal();
}

document.querySelectorAll("[data-open-edit-key]").forEach((button) => {
  button.addEventListener("click", () => {
    document.getElementById(`edit-key-dialog-${button.dataset.openEditKey}`)?.showModal();
  });
});
document.querySelectorAll("[data-close-edit-key]").forEach((button) => {
  button.addEventListener("click", () => {
    document.getElementById(`edit-key-dialog-${button.dataset.closeEditKey}`)?.close();
  });
});
document.querySelectorAll("dialog[data-auto-open='true']").forEach((dialog) => {
  if (!dialog.open) dialog.showModal();
});

(() => {
  const dialog = document.getElementById("revoke-api-key-dialog");
  const form = document.getElementById("revoke-key-form");
  const keyId = document.getElementById("revoke-key-id");
  const label = document.getElementById("revoke-key-label");
  const zones = document.getElementById("revoke-key-zones");
  const lastUsed = document.getElementById("revoke-key-last-used");
  const zoneCountLabel = (count) => {
    const value = Number(count);
    return value === 1
      ? "This key is allowed to use 1 DNS zone."
      : `This key is allowed to use ${value} DNS zones.`;
  };

  document.querySelectorAll("[data-open-revoke-key]").forEach((button) => {
    button.addEventListener("click", () => {
      if (keyId) keyId.value = button.dataset.keyId || "";
      if (label) label.textContent = button.dataset.keyLabel || "";
      if (zones) zones.textContent = zoneCountLabel(button.dataset.zoneCount ?? "0");
      if (lastUsed) lastUsed.textContent = `Last used: ${button.dataset.lastUsed || "Never used"}`;
      dialog?.showModal();
    });
  });
  document.getElementById("revoke-key-close")?.addEventListener("click", () => dialog?.close());
  document.getElementById("revoke-key-cancel")?.addEventListener("click", () => dialog?.close());
})();
