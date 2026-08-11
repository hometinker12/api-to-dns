function bindDialog(openSelector, closeSelector, dialog) {
  document.querySelectorAll(openSelector).forEach((button) => {
    button.addEventListener("click", () => dialog?.showModal());
  });
  document.querySelectorAll(closeSelector).forEach((button) => {
    button.addEventListener("click", () => dialog?.close());
  });
}

function enforceRoleDependencies(form) {
  const roleInputs = Array.from(form.querySelectorAll("input[name='roles']"));
  const inputByRole = new Map(roleInputs.map((input) => [input.value, input]));
  const globalAdminInput = inputByRole.get("global.admin");
  const setMandatoryRole = (input) => {
    input.checked = true;
    input.disabled = true;
    input.closest("label")?.classList.add("role-forced");
  };
  const setForcedReadRole = (input, forced) => {
    if (input.dataset.mandatoryRole === "true" && !forced) {
      setMandatoryRole(input);
      return;
    }
    input.checked = forced;
    input.disabled = forced;
    input.closest("label")?.classList.toggle("role-forced", forced);
  };
  const setGlobalAdminRoles = (forced) => {
    roleInputs.forEach((input) => {
      if (input === globalAdminInput) return;
      if (forced) {
        input.checked = true;
        input.disabled = true;
        input.closest("label")?.classList.add("role-forced");
      } else if (input.dataset.mandatoryRole === "true") {
        setMandatoryRole(input);
      } else {
        input.disabled = false;
        input.closest("label")?.classList.remove("role-forced");
      }
    });
  };
  const syncDependencies = (changedInput) => {
    if (globalAdminInput?.checked) {
      setGlobalAdminRoles(true);
      return;
    }
    setGlobalAdminRoles(false);
    if (changedInput?.dataset.requiresRole) {
      const required = inputByRole.get(changedInput.dataset.requiresRole);
      if (required) setForcedReadRole(required, changedInput.checked);
      return;
    }
    roleInputs.forEach((input) => {
      const required = inputByRole.get(input.dataset.requiresRole);
      if (required && input.checked) setForcedReadRole(required, true);
    });
  };
  roleInputs.forEach((input) => input.addEventListener("change", () => syncDependencies(input)));
  roleInputs.forEach((input) => {
    if (input.dataset.mandatoryRole === "true") setMandatoryRole(input);
  });
  form.addEventListener("submit", () => {
    roleInputs.forEach((input) => {
      if (input.disabled) input.disabled = false;
    });
  });
  syncDependencies();
}

document.querySelectorAll("form").forEach(enforceRoleDependencies);

const createUserDialog = document.getElementById("create-user-dialog");
bindDialog("#open-create-user", "#close-create-user, #cancel-create-user", createUserDialog);
const changePasswordDialog = document.getElementById("change-password-dialog");
bindDialog("#open-change-password", "#close-change-password, #cancel-change-password", changePasswordDialog);
[
  ["edit-roles", "edit-roles-dialog"],
  ["view-roles", "view-roles-dialog"],
  ["reset-password", "reset-password-dialog"],
  ["edit-alert", "edit-alert-dialog"],
].forEach(([name, dialogPrefix]) => {
  const suffix = name.replace(/-([a-z])/g, (_, character) => character.toUpperCase());
  const openKey = `open${suffix}`;
  const closeKey = `close${suffix}`;
  document.querySelectorAll(`[data-open-${name}]`).forEach((button) => {
    button.addEventListener("click", () => {
      document.getElementById(`${dialogPrefix}-${button.dataset[openKey]}`)?.showModal();
    });
  });
  document.querySelectorAll(`[data-close-${name}]`).forEach((button) => {
    button.addEventListener("click", () => {
      document.getElementById(`${dialogPrefix}-${button.dataset[closeKey]}`)?.close();
    });
  });
});
document.querySelectorAll("dialog[data-auto-open='true']").forEach((dialog) => {
  if (!dialog.open) dialog.showModal();
});
const createAlertDialog = document.getElementById("create-alert-dialog");
bindDialog("#open-create-alert", "#close-create-alert, #cancel-create-alert", createAlertDialog);

document.querySelectorAll("form[data-confirm]").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (!window.confirm(form.dataset.confirm)) {
      event.preventDefault();
    }
  });
});
document.getElementById("ssl-enable-form")?.addEventListener("submit", (event) => {
  if (!window.confirm("SSL changes take effect after you restart the application (container or uvicorn process). Continue?")) {
    event.preventDefault();
  }
});

const leStartForm = document.getElementById("le-start-form");
const leAutoEnrollDialog = document.getElementById("le-auto-enroll-dialog");
const leChallengeSelect = leStartForm?.querySelector('[name="challenge_type"]');
const leZoneField = document.getElementById("le-zone-field");
const leZoneSelect = document.getElementById("le-zone-select");
const leRootDnsInput = document.getElementById("le-root-dns-domain");
const syncLeChallengeUi = () => {
  const isHttp = leChallengeSelect?.value === "http-01";
  if (leZoneField) leZoneField.hidden = isHttp;
  if (isHttp && leZoneSelect) leZoneSelect.value = "";
  if (!leRootDnsInput) return;
  const domain = !isHttp && leZoneSelect?.value
    ? leZoneSelect.selectedOptions?.[0]?.dataset?.dnsZone?.trim()
    : "";
  if (domain) leRootDnsInput.value = domain;
  leRootDnsInput.readOnly = Boolean(domain);
  leRootDnsInput.classList.toggle("input-readonly", Boolean(domain));
};
leChallengeSelect?.addEventListener("change", syncLeChallengeUi);
leZoneSelect?.addEventListener("change", syncLeChallengeUi);
syncLeChallengeUi();
const leProgress = document.getElementById("le-auto-enroll-progress");
const leStatus = document.getElementById("le-auto-enroll-status");
const leSubmit = leStartForm?.querySelector('button[type="submit"]');
let lePollTimer = null;
const stopLePoll = () => {
  if (lePollTimer !== null) {
    window.clearInterval(lePollTimer);
    lePollTimer = null;
  }
};
const pollLeProgress = async () => {
  try {
    const response = await fetch("/settings/system/ssl-letsencrypt/progress", {
      credentials: "same-origin",
      headers: { accept: "application/json" },
    });
    if (!response.ok) return;
    const payload = await response.json();
    if (leProgress && typeof payload.percent === "number") leProgress.value = payload.percent;
    if (leStatus && payload.message) leStatus.textContent = payload.message;
    if (!payload.done) return;
    stopLePoll();
    if (payload.error) {
      leAutoEnrollDialog?.close();
      if (leSubmit) leSubmit.disabled = false;
      window.alert(payload.error);
      return;
    }
    if (leProgress) leProgress.value = 100;
    window.location.reload();
  } catch (_error) {
    stopLePoll();
    leAutoEnrollDialog?.close();
    if (leSubmit) leSubmit.disabled = false;
  }
};
leStartForm?.addEventListener("submit", async (event) => {
  const isDnsChallenge = leChallengeSelect?.value === "dns-01" && leStartForm.querySelector('[name="zone_id"]')?.value?.trim();
  if (!isDnsChallenge) return;
  event.preventDefault();
  stopLePoll();
  if (leProgress) leProgress.value = 0;
  if (leSubmit) leSubmit.disabled = true;
  leAutoEnrollDialog?.showModal();
  try {
    const response = await fetch("/settings/system/ssl-letsencrypt/start-async", {
      method: "POST",
      body: new FormData(leStartForm),
      credentials: "same-origin",
      headers: { accept: "application/json" },
    });
    if (!response.ok) throw new Error((await response.json().catch(() => ({}))).detail);
    await pollLeProgress();
    lePollTimer = window.setInterval(pollLeProgress, 1000);
  } catch (error) {
    leAutoEnrollDialog?.close();
    if (leSubmit) leSubmit.disabled = false;
    window.alert(error.message || "Failed to start Let's Encrypt enrollment.");
  }
});
leAutoEnrollDialog?.addEventListener("cancel", (event) => event.preventDefault());

const smtpAnonymous = document.getElementById("smtp-anonymous");
const syncSmtpAnonymous = () => {
  ["smtp-username", "smtp-password"].forEach((id) => {
    const field = document.getElementById(id);
    if (field) field.disabled = Boolean(smtpAnonymous?.checked);
  });
};
smtpAnonymous?.addEventListener("change", syncSmtpAnonymous);
syncSmtpAnonymous();

const syslogEnabled = document.getElementById("syslog-enabled");
const syslogFieldIds = [
  "syslog-host", "syslog-port", "syslog-protocol", "syslog-allow-insecure",
  "syslog-facility", "syslog-minimum-level", "syslog-timeout", "syslog-queue-size",
];
const syncSyslogEnabled = () => {
  if (!syslogEnabled || syslogEnabled.disabled) return;
  syslogFieldIds.forEach((id) => {
    const field = document.getElementById(id);
    if (field) field.disabled = !syslogEnabled.checked;
  });
};
syslogEnabled?.addEventListener("change", syncSyslogEnabled);
syncSyslogEnabled();
document.getElementById("remote-syslog-form")?.addEventListener("submit", () => {
  syslogFieldIds.forEach((id) => {
    const field = document.getElementById(id);
    if (field) field.disabled = false;
  });
});

const backupEncrypt = document.getElementById("backup-encrypt");
const backupEncryptFields = document.getElementById("backup-encrypt-fields");
const backupWarning = document.getElementById("backup-unencrypted-warning");
const backupPassword = document.getElementById("backup-password");
const backupPasswordConfirm = document.getElementById("backup-password-confirm");
const backupExportForm = document.getElementById("backup-export-form");
const encryptionRequired = new Set(["settings", "users", "zones", "api_keys", "ssl_files", "application_secrets"]);
const backupSensitiveCategoriesSelected = () =>
  Array.from(backupExportForm?.querySelectorAll("input[name='categories']:checked") || []).some((input) => encryptionRequired.has(input.value));
const syncBackupEncryptUi = () => {
  const required = backupSensitiveCategoriesSelected();
  if (required && backupEncrypt && !backupEncrypt.checked) backupEncrypt.checked = true;
  if (backupEncrypt) backupEncrypt.disabled = required;
  const enabled = !backupEncrypt || backupEncrypt.checked;
  if (backupEncryptFields) backupEncryptFields.hidden = !enabled;
  if (backupWarning) backupWarning.hidden = enabled;
  if (backupPassword) backupPassword.required = enabled;
  if (backupPasswordConfirm) backupPasswordConfirm.required = enabled;
};
backupEncrypt?.addEventListener("change", syncBackupEncryptUi);
backupExportForm?.querySelectorAll("input[name='categories']").forEach((input) => input.addEventListener("change", syncBackupEncryptUi));
syncBackupEncryptUi();
backupExportForm?.addEventListener("submit", (event) => {
  if (backupSensitiveCategoriesSelected() && backupEncrypt && !backupEncrypt.checked) {
    event.preventDefault();
    window.alert("The selected backup categories require password encryption.");
  } else if (backupEncrypt?.checked && backupPassword?.value !== backupPasswordConfirm?.value) {
    event.preventDefault();
    window.alert("Backup passwords do not match.");
  }
});

const backupImportForm = document.getElementById("backup-import-form");
const backupRestoreDialog = document.getElementById("backup-restore-dialog");
const backupRestoreProgress = document.getElementById("backup-restore-progress");
const backupRestoreStatus = document.getElementById("backup-restore-status");
const backupImportSubmit = document.getElementById("backup-import-submit");
let backupPollTimer = null;
const stopBackupPoll = () => {
  if (backupPollTimer !== null) {
    window.clearInterval(backupPollTimer);
    backupPollTimer = null;
  }
};
const pollBackupProgress = async () => {
  try {
    const response = await fetch("/settings/backup/import/progress", {
      credentials: "same-origin",
      headers: { accept: "application/json" },
    });
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        stopBackupPoll();
        window.setTimeout(() => { window.location.href = "/login"; }, 1500);
      }
      return;
    }
    const payload = await response.json();
    if (backupRestoreProgress && typeof payload.percent === "number") backupRestoreProgress.value = payload.percent;
    if (backupRestoreStatus && payload.message) backupRestoreStatus.textContent = payload.message;
    if (!payload.done) return;
    stopBackupPoll();
    if (payload.error) {
      backupRestoreDialog?.close();
      if (backupImportSubmit) backupImportSubmit.disabled = false;
      window.alert(payload.error);
      return;
    }
    if (backupRestoreProgress) backupRestoreProgress.value = 100;
    if (payload.restarting && backupRestoreStatus) backupRestoreStatus.textContent = "Restarting application…";
    window.setTimeout(() => {
      window.location.href = "/settings?area=backup&section=import";
    }, payload.restarting ? 2500 : 0);
  } catch (_error) {
    if (backupRestoreStatus) backupRestoreStatus.textContent = "Waiting for application restart…";
    window.setTimeout(() => { window.location.href = "/login"; }, 3000);
  }
};
backupImportForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const selected = Array.from(backupImportForm.querySelectorAll('input[name="categories"]:checked')).map((input) => input.value);
  if (selected.some((value) => ["settings", "zones", "ssl_files"].includes(value)) && !selected.includes("application_secrets")) {
    window.alert("Restoring settings, DNS zones, or SSL files requires Application secrets.");
    return;
  }
  stopBackupPoll();
  if (backupRestoreProgress) backupRestoreProgress.value = 0;
  if (backupImportSubmit) backupImportSubmit.disabled = true;
  backupRestoreDialog?.showModal();
  try {
    const response = await fetch("/settings/backup/import-async", {
      method: "POST",
      body: new FormData(backupImportForm),
      credentials: "same-origin",
      headers: { accept: "application/json" },
    });
    if (!response.ok) throw new Error((await response.json().catch(() => ({}))).detail);
    await pollBackupProgress();
    backupPollTimer = window.setInterval(pollBackupProgress, 1000);
  } catch (error) {
    backupRestoreDialog?.close();
    if (backupImportSubmit) backupImportSubmit.disabled = false;
    window.alert(error.message || "Failed to start restore.");
  }
});
backupRestoreDialog?.addEventListener("cancel", (event) => event.preventDefault());
