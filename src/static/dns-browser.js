(() => {
  const config = document.getElementById("dns-browser-config");
  if (!config) return;
  const zoneId = config.dataset.zoneId;
  const canUpdate = config.dataset.canUpdate === "true";
  const cloudflareProxyEnabled = config.dataset.cloudflareProxyEnabled === "true";
  const typeOptions = JSON.parse(config.dataset.recordTypeOptions || "[]");
  const searchForm = document.getElementById("dns-browser-search");
  const recordName = document.getElementById("record-name");
  const recordType = document.getElementById("record-type");
  const status = document.getElementById("dns-browser-status");
  const results = document.getElementById("dns-browser-results");
  const tbody = document.getElementById("dns-browser-tbody");
  const recordDialog = document.getElementById("record-dialog");
  const recordForm = document.getElementById("record-form");
  const formMode = document.getElementById("record-form-mode");
  const formName = document.getElementById("form-record-name");
  const formType = document.getElementById("form-record-type");
  const formTtl = document.getElementById("form-ttl");
  const formValues = document.getElementById("form-values");
  const formValuesHelp = document.getElementById("form-values-help");
  const formError = document.getElementById("record-form-error");
  const formStatus = document.getElementById("record-form-status");
  const formWarning = document.getElementById("record-form-warning");
  const addValueRowBtn = document.getElementById("add-value-row");
  const proxyIndicator = document.getElementById("cloudflare-proxy-indicator");
  const deleteDialog = document.getElementById("delete-record-dialog");
  const deleteSummary = document.getElementById("delete-record-summary");
  const searchSubmit = searchForm?.querySelector('button[type="submit"]');
  const mutableMeta = Object.fromEntries(typeOptions.filter((option) => option.value).map((option) => [option.value, option]));
  let lastSearch;
  let pendingDelete;
  let controller;
  let requestId = 0;

  const setStatus = (kind, message) => {
    if (!status) return;
    status.hidden = !message;
    status.className = `alert${kind ? ` ${kind}` : ""}`;
    status.textContent = message || "";
  };
  const errorMessage = (payload, fallback) =>
    payload?.message || payload?.detail?.message || (typeof payload?.detail === "string" ? payload.detail : fallback);
  const escapeHtml = (value) => String(value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const fieldsForValue = (type, value) => {
    const parts = String(value || "").trim().split(/\s+/);
    if (type === "MX") return { priority: parts[0] || "10", exchange: parts.slice(1).join(" ") };
    if (type === "SRV") return { priority: parts[0] || "0", weight: parts[1] || "0", port: parts[2] || "0", target: parts.slice(3).join(" ") };
    if (type === "CAA") return { flags: parts[0] || "0", tag: parts[1] || "issue", value: parts.slice(2).join(" ") };
    if (["A", "AAAA"].includes(type)) return { address: value || "" };
    if (type === "CNAME") return { target: value || "" };
    if (["NS", "PTR"].includes(type)) return { hostname: value || "" };
    return { value: value || "" };
  };
  const serializeValue = (type, row) => {
    const value = (name) => row.querySelector(`[name="${name}"]`)?.value.trim() || "";
    if (type === "MX") return `${Number(value("priority"))} ${value("exchange")}`;
    if (type === "SRV") return `${Number(value("priority"))} ${Number(value("weight"))} ${Number(value("port"))} ${value("target")}`;
    if (type === "CAA") return `${Number(value("flags"))} ${value("tag")} ${value("value")}`;
    if (["A", "AAAA"].includes(type)) return value("address");
    if (type === "CNAME") return value("target");
    if (["NS", "PTR"].includes(type)) return value("hostname");
    return value("value");
  };
  const addValueRow = (type, initial = {}) => {
    const meta = mutableMeta[type] || { fields: ["value"], multiple: true };
    const row = document.createElement("div");
    row.className = "dns-browser-value-row";
    if ((meta.fields || []).length <= 1) row.classList.add("dns-browser-value-row-single");
    meta.fields.forEach((field) => {
      const label = document.createElement("label");
      label.textContent = field === "address" ? "IP Address" : field;
      const input = document.createElement("input");
      input.name = field;
      input.required = true;
      input.autocomplete = "off";
      input.type = ["priority", "weight", "port", "flags"].includes(field) ? "number" : "text";
      if (input.type === "number") input.min = "0";
      input.value = initial[field] ?? (field === "priority" ? "10" : "");
      label.appendChild(input);
      row.appendChild(label);
    });
    if (meta.multiple) {
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "danger dns-browser-remove-value";
      remove.textContent = "X";
      remove.setAttribute("aria-label", "Remove value");
      remove.addEventListener("click", () => {
        if (formValues.children.length > 1) row.remove();
      });
      row.appendChild(remove);
    }
    formValues.appendChild(row);
  };
  const rebuildValueRows = (type, values = []) => {
    formValues.innerHTML = "";
    const help = { A: "IPv4 address, e.g. 192.0.2.10", AAAA: "IPv6 address", CNAME: "Canonical hostname target", TXT: "Text string", MX: "Priority and mail exchange host", NS: "Name server hostname (non-apex only)", SRV: "Priority, weight, port, and target", CAA: "Flags, tag, and value", PTR: "Pointer hostname (reverse zones only)" };
    formValuesHelp.textContent = help[type] || "";
    (values.length ? values : [""]).forEach((value) => addValueRow(type, fieldsForValue(type, value)));
    addValueRowBtn.hidden = !(mutableMeta[type] || { multiple: true }).multiple;
    proxyIndicator.hidden = !(cloudflareProxyEnabled && ["A", "AAAA", "CNAME"].includes(type));
  };
  const openRecordDialog = (mode, record) => {
    formMode.value = mode;
    formError.hidden = true;
    formWarning.hidden = mode !== "replace";
    document.getElementById("record-dialog-title").textContent = mode === "replace" ? "Edit record" : "Add record";
    formName.value = record?.record_name || recordName.value.trim() || "";
    formType.value = record?.record_type || "A";
    formTtl.value = record?.ttl ?? 300;
    formName.readOnly = mode === "replace";
    formType.disabled = mode === "replace";
    rebuildValueRows(formType.value, record?.values || []);
    recordDialog.showModal();
  };
  const setBusy = (busy) => {
    if (searchSubmit) searchSubmit.disabled = busy;
    if (recordName) recordName.readOnly = busy;
    if (recordType) recordType.disabled = busy;
  };
  const renderSearch = async (url) => {
    controller?.abort();
    controller = new AbortController();
    const currentId = ++requestId;
    setStatus("", "Searching…");
    results.hidden = true;
    tbody.innerHTML = "";
    setBusy(true);
    try {
      const response = await fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin", signal: controller.signal });
      const payload = await response.json();
      if (currentId !== requestId) return;
      if (!response.ok) {
        setStatus("error", errorMessage(payload, "DNS lookup failed."));
        return;
      }
      lastSearch = url;
      const records = payload.records || [];
      if (!records.length) {
        setStatus("success", payload.message || "No matching records found.");
        return;
      }
      setStatus("success", `Found ${records.length} record set(s).${payload.truncated ? " Showing the first 100; narrow the search to see more." : ""}`);
      records.forEach((record) => {
        const row = document.createElement("tr");
        const values = (record.values || []).map((value) => `<li><code>${escapeHtml(value)}</code></li>`).join("");
        const mutable = Boolean(mutableMeta[record.record_type]?.mutable);
        const actions = canUpdate && mutable
          ? '<div class="action-cell dns-browser-action-cell"><button type="button" class="secondary" data-edit>Edit</button><button type="button" class="danger" data-delete>Delete</button></div>'
          : "—";
        row.innerHTML = `<td><code>${escapeHtml(record.record_name)}</code></td><td><code>${escapeHtml(record.record_type)}</code></td><td>${record.ttl != null ? `<code>${escapeHtml(record.ttl)}</code>` : "—"}</td><td><ul class="dns-browser-value-list">${values}</ul></td><td class="actions-column">${actions}</td>`;
        row.querySelector("[data-edit]")?.addEventListener("click", () => openRecordDialog("replace", record));
        row.querySelector("[data-delete]")?.addEventListener("click", () => {
          pendingDelete = { record_name: record.record_name, record_type: record.record_type };
          deleteSummary.textContent = `${record.record_name} ${record.record_type}`;
          deleteDialog.showModal();
        });
        tbody.appendChild(row);
      });
      results.hidden = false;
    } catch (error) {
      if (error?.name !== "AbortError" && currentId === requestId) setStatus("error", "DNS lookup failed.");
    } finally {
      if (currentId === requestId) setBusy(false);
    }
  };
  const mutate = async (method, payload) => {
    const response = await fetch(`/zones/${zoneId}/records`, { method, headers: { "Content-Type": "application/json", Accept: "application/json" }, credentials: "same-origin", body: JSON.stringify(payload) });
    const result = await response.json();
    if (!response.ok) throw new Error(errorMessage(result, "DNS operation failed."));
    if (lastSearch) await renderSearch(lastSearch);
    return result;
  };
  searchForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const query = new URLSearchParams();
    if (recordName.value.trim()) query.set("record_name", recordName.value.trim());
    if (recordType.value) query.set("record_type", recordType.value);
    await renderSearch(`/zones/${zoneId}/records/search?${query}`);
  });
  document.getElementById("add-record-btn")?.addEventListener("click", () => openRecordDialog("create"));
  formType?.addEventListener("change", () => rebuildValueRows(formType.value));
  addValueRowBtn?.addEventListener("click", () => addValueRow(formType.value));
  ["record-dialog-close", "record-dialog-cancel"].forEach((id) => document.getElementById(id)?.addEventListener("click", () => recordDialog.close()));
  ["delete-record-close", "delete-record-cancel"].forEach((id) => document.getElementById(id)?.addEventListener("click", () => deleteDialog.close()));
  const setRecordFormBusy = (busy, mode) => {
    recordDialog.querySelectorAll("input, select, button").forEach((element) => {
      if (busy) {
        element.dataset.recordFormDisabled = String(element.disabled);
        element.disabled = true;
      } else {
        element.disabled = element.dataset.recordFormDisabled === "true";
        delete element.dataset.recordFormDisabled;
      }
    });
    formStatus.hidden = !busy;
    formStatus.textContent = busy
      ? (mode === "replace" ? "Updating record..." : "Adding new record...")
      : "";
  };
  recordForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    formError.hidden = true;
    const mode = formMode.value;
    const payload = { record_name: formName.value.trim(), record_type: formType.value, ttl: Number(formTtl.value), values: Array.from(formValues.querySelectorAll(".dns-browser-value-row")).map((row) => serializeValue(formType.value, row)) };
    try {
      setRecordFormBusy(true, mode);
      await mutate(mode === "replace" ? "PUT" : "POST", payload);
      recordDialog.close();
      setStatus("success", mode === "replace" ? "Record updated." : "Record created.");
    } catch (error) {
      formError.hidden = false;
      formError.textContent = error.message || "DNS operation failed.";
    } finally {
      setRecordFormBusy(false, mode);
    }
  });
  document.getElementById("delete-record-confirm")?.addEventListener("click", async () => {
    if (!pendingDelete) return;
    try {
      await mutate("DELETE", pendingDelete);
      deleteDialog.close();
      setStatus("success", "Record deleted.");
    } catch (error) {
      deleteDialog.close();
      setStatus("error", error.message || "Delete failed.");
    }
  });
})();
