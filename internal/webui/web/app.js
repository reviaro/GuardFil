"use strict";
(function () {
  const $ = (id) => document.getElementById(id);
  const setText = (id, text) => { if ($(id).textContent !== text) $(id).textContent = text; };
  const PLACEHOLDERS = {
    shell: "",
    command: "e.g. git status --short",
    "command-prefix": "e.g. git status",
    tool: "server.tool, e.g. testmcp.write_canary",
    files: "folder, e.g. /workspace/notes",
    reads: "folder, e.g. /workspace/docs",
    website: "https URL with a path, e.g. https://example.com/api/**",
  };
  let yamlDirty = false;
  let privacyDirty = false;
  let contentJsonDirty = false;
  let activeTab = "policy";
  let currentContentRules = null;
  let editingListId = null;
  let timer = null;
  let refreshing = false;
  let savingContent = false;
  const rendered = new Map();
  let sessionToken = sessionStorage.getItem("guardfil-session") || "";

  async function api(method, path, body) {
    const opts = { method, headers: {}, credentials: "same-origin" };
    if (sessionToken) opts.headers["X-GuardFil-Session"] = sessionToken;
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (res.status === 401 && path !== "/api/login") { showLogin(); throw new Error("login required"); }
    if (!res.ok) throw new Error((data && data.error) || res.statusText);
    return data;
  }

  // Keep focus and scroll position when polling returns unchanged data.
  function changed(section, value) {
    const key = JSON.stringify(value);
    if (rendered.get(section) === key) return false;
    rendered.set(section, key);
    return true;
  }

  function busy(handler, label = "Saving…") {
    return async (event) => {
      event.preventDefault();
      const source = event.currentTarget;
      const button = source.tagName === "FORM" ? source.querySelector('button[type="submit"]') : source;
      if (button.disabled) return;
      const contentMutation = source.closest("#tab-content") && source.id !== "try-form";
      if (contentMutation && savingContent) return;
      if (contentMutation) savingContent = true;
      const text = button.textContent;
      const peers = contentMutation ? $("tab-content").querySelectorAll("button") : button.closest(".pending-item")?.querySelectorAll("button") || [button];
      for (const peer of peers) peer.disabled = true;
      button.textContent = label;
      source.setAttribute("aria-busy", "true");
      try { await handler(event); }
      finally {
        if (contentMutation) savingContent = false;
        for (const peer of peers) peer.disabled = false;
        if (button.textContent === label) button.textContent = text;
        source.removeAttribute("aria-busy");
      }
    };
  }

  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") e.className = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v);
    }
    for (const c of children) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return e;
  }

  function flash(msg, isError) {
    const f = $("flash");
    setText("flash-text", msg);
    f.className = "flash" + (isError ? " error" : "");
    clearTimeout(flash.t);
    if (!isError) flash.t = setTimeout(() => f.classList.add("hidden"), 5000);
  }

  function showLogin() {
    sessionToken = "";
    sessionStorage.removeItem("guardfil-session");
    clearInterval(timer);
    timer = null;
    $("app").classList.add("hidden");
    $("login").classList.remove("hidden");
    rendered.clear();
    $("token").focus();
  }

  function showApp() {
    $("login").classList.add("hidden");
    $("app").classList.remove("hidden");
    refresh();
    if (activeTab === "content") refreshContent();
    if (!timer) timer = setInterval(refresh, 1500);
  }

  function callLabel(d) {
    if (d.kind === "file_write") return "write " + (d.paths || []).join(", ");
    if (d.kind === "file_read") return "read " + (d.paths || []).join(", ");
    if (d.kind === "shell") return "shell command";
    if (d.kind === "mcp") return "tool " + (d.tool || "?");
    if (d.kind === "filter") return "result of " + (d.tool || "?");
    return d.kind || "?";
  }

  function since(iso) {
    const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
    return s < 60 ? s + " s" : Math.round(s / 60) + " min";
  }

  function renderPending(st) {
    renderFileGrants(st.file_grants || []);
    $("ask-off").classList.toggle("hidden", st.ask_enabled);
    setText("pending-count", st.pending.length + " pending");
    $("pending-count").className = "tag" + (st.pending.length ? " askme" : "");
    if (!changed("pending", st.pending)) {
      for (const row of $("pending").children) {
        const p = st.pending.find((item) => item.id === row.dataset.id);
        if (p) row.querySelector(".waiting-time").textContent = "waiting " + since(p.since);
      }
      return;
    }
    const ul = $("pending");
    ul.replaceChildren();
    $("pending-empty").classList.toggle("hidden", st.pending.length > 0);
    for (const p of st.pending) {
      const answer = (decision, scope = "once") => async () => {
        try {
          await api("POST", "/api/approvals/" + encodeURIComponent(p.id), { decision, scope });
          flash(scope === "session" ? "File access allowed for this session." : decision === "allow" ? "Allowed." : "Denied.");
        } catch (e) { flash(e.message, true); }
        refresh();
      };
      ul.append(el("li", { class: "pending-item", "data-id": p.id },
        el("div", {},
          el("strong", {}, callLabel(p)), " ",
          el("span", { class: "tag mono" }, p.principal || "codex-agent"),
          p.detail ? el("code", { class: "detail" }, p.detail) : "",
          el("div", { class: "muted" }, "rule " + (p.rule_ids || []).join(", ") + " · ", el("span", { class: "waiting-time" }, "waiting " + since(p.since)),
            " · blocks at " + new Date(p.expires_at).toLocaleTimeString())),
        el("div", { class: "row" },
          p.session_grant ? el("button", { class: "allow session-allow", onclick: busy(answer("allow", "session"), "Allowing…") }, "Allow for session") : "",
          el("button", { class: "allow", onclick: busy(answer("allow"), "Allowing…") }, p.session_grant ? "Allow once" : "Allow"),
          el("button", { class: "deny", onclick: busy(answer("deny"), "Denying…") }, "Deny"))));
    }
  }

  function renderFileGrants(grants) {
    if (!changed("file-grants", grants)) return;
    $("file-grants-section").classList.toggle("hidden", grants.length === 0);
    const list = $("file-grants");
    list.replaceChildren();
    for (const grant of grants) {
      const revoke = async () => {
        try {
          await api("POST", "/api/file-grants/" + encodeURIComponent(grant.session) + "/revoke", {});
          flash("File approvals cleared. Further access will ask again.");
        } catch (e) { flash(e.message, true); }
        refresh();
      };
      list.append(el("li", {},
        el("span", {}, grant.principal + " · " + grant.reads + " read, " + grant.writes + " write · session " + grant.session.slice(0, 8)),
        el("button", { onclick: busy(revoke, "Clearing…") }, "Clear file approvals")));
    }
  }

  function renderRules(st) {
    if (!changed("rules", st.rules)) return;
    const tb = $("rules");
    tb.replaceChildren();
    if (st.rules.length === 0) {
      tb.append(el("tr", {}, el("td", { colspan: "5", class: "muted" }, "No rules: everything is blocked.")));
    }
    for (const r of st.rules) {
      const del = async () => {
        if (!confirm("Delete rule " + r.id + "?")) return;
        try {
          await api("POST", "/api/rules", { op: "delete", id: r.id });
          flash("Rule deleted.");
        } catch (e) { flash(e.message, true); }
        refresh();
      };
      tb.append(el("tr", {},
        el("td", {}, el("span", { class: "tag " + r.action.replace(/\s/g, "").toLowerCase() }, r.action)),
        el("td", { class: "mono" }, r.principal || "codex-agent"),
        el("td", {}, r.target),
        el("td", { class: "mono" }, r.value, r.when ? el("div", { class: "when-rule" }, "when " + r.when) : ""),
        el("td", {}, el("button", { class: "ghost small", onclick: busy(del, "Deleting…"), title: r.id, "aria-label": "Delete rule " + r.id }, "Delete"))));
    }
  }

  function renderDecisions(st) {
    if (!changed("decisions", st.decisions)) return;
    const tb = $("decisions");
    tb.replaceChildren();
    $("decisions-empty").classList.toggle("hidden", st.decisions.length > 0);
    for (const d of st.decisions) {
      let result = d.effect === "ALLOW" ? "Allowed" : d.effect === "FILTERED" ? "Result filtered" : "Blocked";
      if (d.effect === "FILTERED") result += " · " + (d.redactions || 0) + " secret" + (d.redactions === 1 ? "" : "s") + " removed";
      if ((d.reasons || []).includes("POLICY_FILTERED")) result += " · result filtered";
      if (d.monitored) result += " · monitored";
      if (d.asked) result += " · asked (" + d.asked + ")";
      tb.append(el("tr", { class: d.effect === "BLOCK" ? "blocked" : "ok" },
        el("td", { class: "mono" }, d.time ? new Date(d.time).toLocaleTimeString() : ""),
        el("td", { class: "mono" }, d.principal || "codex-agent"),
        el("td", {}, el("span", { class: "result" }, result)),
        el("td", {}, callLabel(d)),
        el("td", { class: "mono" }, [...(d.rule_ids || []), ...(d.reasons || [])].join(" "))));
    }
  }

  function renderVersions(st) {
    if (!changed("versions", [st.policy_version, st.versions])) return;
    const ul = $("versions");
    ul.replaceChildren();
    const restore = (v) => async () => {
      if (!confirm("Put " + (v === 0 ? "the original policy file" : "version " + v) + " back in force?")) return;
      try {
        await api("POST", "/api/policy/restore", { version: v });
        flash("Restored.");
      } catch (e) { flash(e.message, true); }
      refresh();
    };
    for (const v of st.versions) {
      ul.append(el("li", {},
        el("span", { class: "mono" }, "v" + v.version), " ",
        el("span", { class: "history-note" }, v.note), " ",
        el("span", { class: "muted history-time" }, new Date(v.time).toLocaleString()), " ",
        v.version === st.policy_version ? el("span", { class: "tag allow" }, "in force")
          : el("button", { class: "ghost small", onclick: busy(restore(v.version), "Restoring…") }, "Restore")));
    }
    ul.append(el("li", {},
      el("span", { class: "mono" }, "v0"), " ", el("span", {}, "the policy file"), " ",
      st.policy_version === 0 ? el("span", { class: "tag allow" }, "in force")
        : el("button", { class: "ghost small", onclick: busy(restore(0), "Restoring…") }, "Restore")));
  }

  let toolsKey = "";
  let tools = [];
  function renderTools(st) {
    const key = (st.tools || []).map((t) => t.id).join(",");
    if (key === toolsKey) return;
    toolsKey = key;
    tools = st.tools || [];
    $("tool-list").replaceChildren(...tools.map((t) =>
      el("option", { value: t.id }, t.description || t.id)));
    renderFields();
  }

  // Suggest the chosen tool's numeric arguments, and products of two, for an amount condition.
  function renderFields() {
    const t = tools.find((x) => x.id === $("r-value").value.trim());
    const nums = t ? Object.keys(t.arguments || {}).filter((a) =>
      ["integer", "decimal"].includes(t.arguments[a].type)).sort() : [];
    const opts = [...nums];
    for (let i = 0; i < nums.length; i++)
      for (let j = i + 1; j < nums.length; j++) opts.push(nums[i] + " * " + nums[j]);
    $("field-list").replaceChildren(...opts.map((o) => el("option", { value: o })));
  }

  let principalsKey = "";
  function renderPrincipals(st) {
    const princs = st.principals || ["codex-agent"];
    const key = princs.join(",");
    if (key === principalsKey) return;
    principalsKey = key;
    const curVal = $("r-principal").value;
    const opts = princs.map((p) => el("option", { value: p }, p));
    opts.push(el("option", { value: "__new__" }, "+ New agent..."));
    $("r-principal").replaceChildren(...opts);
    if (princs.includes(curVal) || curVal === "__new__") {
      $("r-principal").value = curVal;
    }
    $("r-principal-new-field").classList.toggle("hidden", $("r-principal").value !== "__new__");
  }

  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    let st;
    try {
      st = await api("GET", "/api/state");
      $("connection-error").classList.add("hidden");
    } catch (e) {
      $("connection-error").classList.remove("hidden");
      $("status").textContent = "Connection interrupted · retrying";
      return;
    } finally { refreshing = false; }
    setText("status", "policy v" + st.policy_version + " · " + st.rules.length +
      (st.rules.length === 1 ? " rule" : " rules") + " · ask me " +
      (st.ask_enabled ? "on" : "off"));
    renderPending(st);
    renderRules(st);
    renderPrincipals(st);
    renderDecisions(st);
    renderVersions(st);
    renderTools(st);
  if (!privacyDirty) $("local-only-paths").value = (st.local_only_paths || []).join("\n");
  const privateSessions = st.private_sessions || [];
  $("private-sessions-section").classList.toggle("hidden", privateSessions.length === 0);
  if (changed("private-sessions", privateSessions)) {
    $("private-sessions").replaceChildren(...privateSessions.map(s =>
      el("li", {}, el("span", {}, s.principal + " · " + s.session), el("span", {class: "tag"}, "Cloud blocked"))));
  }
    if (!yamlDirty) $("yaml").value = st.policy_yaml;
  }

  $("login-form").addEventListener("submit", busy(async (ev) => {
    ev.preventDefault();
    $("login-error").textContent = "";
    try {
      const login = await api("POST", "/api/login", { token: $("token").value });
      sessionToken = login.session_token;
      sessionStorage.setItem("guardfil-session", sessionToken);
      $("token").value = "";
      showApp();
    } catch (e) { $("login-error").textContent = e.message; }
  }, "Logging in…"));

  $("flash-dismiss").addEventListener("click", () => $("flash").classList.add("hidden"));

  $("logout").addEventListener("click", async () => {
    try { await api("POST", "/api/logout", {}); } catch (e) { /* already out */ }
    showLogin();
  });

  $("r-principal").addEventListener("change", () => {
    const isNew = $("r-principal").value === "__new__";
    $("r-principal-new-field").classList.toggle("hidden", !isNew);
    if (isNew) $("r-principal-new").focus();
  });

  $("r-target").addEventListener("change", () => {
    const t = $("r-target").value;
    $("website-help").classList.toggle("hidden", t !== "website");
    const commandRule = t === "command" || t === "command-prefix";
    $("command-help").classList.toggle("hidden", !commandRule);
    $("command-help").textContent = (t === "command-prefix"
      ? "Matches the command and its first arguments: git status also matches git status --short. "
      : "Matches the command and every argument exactly: git status does not match git status --short. ") +
      "Once this agent has command rules, every command needs an Allow, Monitor or Ask me match. Blocks and existing all-shell approvals still apply. Enter a single command; quote arguments containing spaces.";
    $("filesystem-help").classList.toggle("hidden", t !== "files" && t !== "reads");
    $("r-value").placeholder = t === "shell" ? "All shell commands" : PLACEHOLDERS[t];
    $("r-value").disabled = t === "shell";
    if (t === "tool") $("r-value").setAttribute("list", "tool-list");
    else $("r-value").removeAttribute("list");
    $("r-when").classList.toggle("hidden", t !== "tool");
  });
  $("r-value").addEventListener("input", renderFields);
  $("r-value").disabled = true;
  $("r-value").placeholder = "All shell commands";

  $("add-rule").addEventListener("submit", busy(async (ev) => {
    ev.preventDefault();
    try {
      let princ = $("r-principal").value;
      if (princ === "__new__") {
        princ = $("r-principal-new").value.trim();
        if (!princ) throw new Error("enter an agent name");
      }
      const req = { op: "add", principal: princ, action: $("r-action").value, target: $("r-target").value, value: $("r-value").value };
      if (req.target === "tool" && ($("r-field").value.trim() || $("r-amount").value.trim())) {
        req.field = $("r-field").value;
        req.operator = $("r-op").value;
        req.amount = $("r-amount").value;
      }
      await api("POST", "/api/rules", req);
      $("r-value").value = "";
      $("r-field").value = "";
      $("r-amount").value = "";
      $("r-principal-new").value = "";
      flash("Rule added; it applies to the next call.");
    } catch (e) { flash(e.message, true); }
    refresh();
  }, "Adding…"));

  $("yaml").addEventListener("input", () => { yamlDirty = true; });
  $("local-only-paths").addEventListener("input", () => { privacyDirty = true; });
  $("privacy-discard").addEventListener("click", () => { privacyDirty = false; refresh(); });
  $("privacy-form").addEventListener("submit", busy(async () => {
    try {
      const paths = $("local-only-paths").value.split("\n").map(p => p.trim()).filter(Boolean);
      await api("POST", "/api/privacy", {paths});
      privacyDirty = false;
      flash("Local-only paths saved; file permissions still apply.");
    } catch (e) { flash(e.message, true); }
    refresh();
  }));
  $("yaml-reload").addEventListener("click", () => { yamlDirty = false; refresh(); });
  $("yaml-save").addEventListener("click", busy(async () => {
    try {
      await api("POST", "/api/policy", { yaml: $("yaml").value, note: $("yaml-note").value });
      yamlDirty = false;
      $("yaml-note").value = "";
      flash("Policy saved; it applies to the next call.");
    } catch (e) { flash(e.message, true); }
    refresh();
  }, "Saving…"));

  // ---- Content tab

  function switchTab(tab) {
    activeTab = tab;
    for (const name of ["policy", "content"]) {
      const button = $("tab-" + name + "-btn");
      button.classList.toggle("active", tab === name);
      button.setAttribute("aria-selected", String(tab === name));
      button.tabIndex = tab === name ? 0 : -1;
    }
    $("tab-policy").classList.toggle("hidden", tab !== "policy");
    $("tab-content").classList.toggle("hidden", tab !== "content");
    if (tab === "content") {
      refreshContent();
    } else {
      refresh();
    }
  }

  async function refreshContent() {
    let data;
    try { data = await api("GET", "/api/content"); } catch (e) {
      currentContentRules = null;
      flash("Content rules could not be loaded. Select Content to retry.", true);
      return;
    }
    currentContentRules = data.rules || { schema_version: 1, lists: [], injection: { action: "none", tools: ["*"] } };
    renderContentTab(data);
  }

  function renderContentTab(data) {
    const rules = data.rules || {};
    const inj = rules.injection || { action: "none", tools: ["*"] };
    $("inj-action").value = inj.action || "none";
    $("inj-tools").value = (inj.tools && inj.tools.join(", ")) || "*";

    const tbody = $("content-lists");
    tbody.replaceChildren();
    const lists = rules.lists || [];
    $("content-lists-empty").classList.toggle("hidden", lists.length > 0);

    for (const l of lists) {
      const cls = l.action === "block" ? "block" : l.action === "filter" ? "filter" :
                  l.action === "monitor" ? "monitor" : "askme";
      const wCount = (l.words && l.words.length) || 0;
      const pCount = (l.patterns && l.patterns.length) || 0;
      let summary = "";
      if (wCount > 0) summary += wCount + " word" + (wCount > 1 ? "s" : "");
      if (pCount > 0) summary += (summary ? ", " : "") + pCount + " pattern" + (pCount > 1 ? "s" : "");

      tbody.append(el("tr", {},
        el("td", {}, el("strong", {}, l.name), el("div", { class: "muted mono" }, l.id)),
        el("td", {}, el("span", { class: "tag " + cls }, l.action)),
        el("td", {}, el("span", { class: "muted" }, l.direction)),
        el("td", { class: "mono" }, (l.tools || []).join(", ")),
        el("td", { class: "mono" }, summary),
        el("td", { class: "row" },
          el("button", { class: "ghost small", onclick: () => editList(l) }, "Edit"),
          el("button", { class: "ghost small", onclick: busy(() => deleteList(l.id), "Deleting…") }, "Delete"),
        ),
      ));
    }

    const ul = $("content-versions");
    ul.replaceChildren();
    for (const v of (data.versions || [])) {
      const isCur = v.version === data.version;
      ul.append(el("li", { class: "row" },
        el("span", { class: "muted" }, "#" + v.version),
        el("span", {}, v.note || "(no note)"),
        el("span", { class: "muted" }, since(v.time) + " ago"),
        isCur ? el("span", { class: "tag allow" }, "current") :
                el("button", { class: "ghost small", onclick: busy(() => restoreContentVersion(v.version), "Restoring…") }, "Restore"),
      ));
    }

    if (!contentJsonDirty) {
      $("content-json").value = JSON.stringify(rules, null, 2);
    }
  }

  function editList(l) {
    editingListId = l.id;
    $("content-form-title").textContent = "Edit list: " + l.name;
    $("cl-name").value = l.name;
    $("cl-id").value = l.id;
    $("cl-id").disabled = true;
    $("cl-action").value = l.action;
    $("cl-direction").value = l.direction;
    $("cl-tools").value = (l.tools || []).join(", ");
    $("cl-words").value = (l.words || []).join(", ");
    $("cl-patterns").value = (l.patterns || []).join(", ");
    $("cl-case").checked = !!l.case_sensitive;
    $("cl-submit").textContent = "Save list";
    $("cl-cancel").classList.remove("hidden");
    $("cl-name").focus();
  }

  function cancelEditList() {
    editingListId = null;
    $("content-form-title").textContent = "Add word or pattern list";
    $("cl-name").value = "";
    $("cl-id").value = "";
    $("cl-id").disabled = false;
    $("cl-tools").value = "*";
    $("cl-words").value = "";
    $("cl-patterns").value = "";
    $("cl-case").checked = false;
    $("cl-submit").textContent = "Add list";
    $("cl-cancel").classList.add("hidden");
  }

  async function deleteList(id) {
    if (!currentContentRules || !confirm("Delete content list " + id + "?")) return;
    const next = structuredClone(currentContentRules);
    next.lists = (next.lists || []).filter(l => l.id !== id);
    try {
      await api("PUT", "/api/content", { rules: next, note: "deleted list " + id });
      if (editingListId === id) cancelEditList();
      flash("Deleted list " + id + ".");
      await refreshContent();
    } catch (e) { flash(e.message, true); }
  }

  async function restoreContentVersion(version) {
    if (!confirm("Put content rules version " + version + " back in force?")) return;
    try {
      await api("POST", "/api/content/restore", { version });
      cancelEditList();
      contentJsonDirty = false;
      flash("Restored content rules version " + version + ".");
      await refreshContent();
    } catch (e) { flash(e.message, true); }
  }

  $("tab-policy-btn").addEventListener("click", () => switchTab("policy"));
  $("tab-content-btn").addEventListener("click", () => switchTab("content"));

  document.querySelector(".tabs").addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const tab = event.key === "Home" ? "policy" : event.key === "End" ? "content" : activeTab === "policy" ? "content" : "policy";
    switchTab(tab);
    $("tab-" + tab + "-btn").focus();
  });

  // Content tab listeners
  $("injection-form").addEventListener("submit", busy(async (ev) => {
    ev.preventDefault();
    if (!currentContentRules) return;
    const action = $("inj-action").value;
    const tools = $("inj-tools").value.split(",").map(s => s.trim()).filter(Boolean);
    const next = structuredClone(currentContentRules);
    next.injection = { action, tools: tools.length ? tools : ["*"] };
    try {
      await api("PUT", "/api/content", { rules: next, note: "updated injection rule" });
      flash("Injection rule updated; applies to next call.");
      await refreshContent();
    } catch (e) { flash(e.message, true); }
  }, "Updating…"));

  $("cl-cancel").addEventListener("click", cancelEditList);

  $("add-content-list").addEventListener("submit", busy(async (ev) => {
    ev.preventDefault();
    if (!currentContentRules) return;
    const name = $("cl-name").value.trim();
    const id = $("cl-id").value.trim();
    const action = $("cl-action").value;
    const direction = $("cl-direction").value;
    const tools = $("cl-tools").value.split(",").map(s => s.trim()).filter(Boolean);
    const words = $("cl-words").value.split(",").map(s => s.trim()).filter(Boolean);
    const patterns = $("cl-patterns").value.split(",").map(s => s.trim()).filter(Boolean);
    const caseSensitive = $("cl-case").checked;

    if (!words.length && !patterns.length) {
      flash("List must have at least one word or pattern.", true);
      return;
    }

    const listObj = {
      id,
      name,
      action,
      direction,
      tools: tools.length ? tools : ["*"],
      words,
      patterns,
      case_sensitive: caseSensitive,
    };

    const next = structuredClone(currentContentRules);
    if (editingListId) {
      const idx = (next.lists || []).findIndex(l => l.id === editingListId);
      if (idx >= 0) next.lists[idx] = listObj;
    } else {
      next.lists = next.lists || [];
      next.lists.push(listObj);
    }

    try {
      await api("PUT", "/api/content", { rules: next, note: (editingListId ? "updated" : "added") + " list " + id });
      cancelEditList();
      flash("Saved content list " + id + ".");
      await refreshContent();
    } catch (e) { flash(e.message, true); }
  }, "Saving…"));

  $("try-form").addEventListener("submit", busy(async (ev) => {
    ev.preventDefault();
    const tool = $("try-tool").value.trim() || "*";
    const direction = $("try-dir").value;
    const text = $("try-text").value;
    try {
      const res = await api("POST", "/api/content/try", { tool, direction, text });
      $("try-result").classList.remove("hidden");
      const act = $("try-action");
      act.textContent = res.action;
      act.className = "tag " + (res.action === "block" ? "block" : res.action === "filter" ? "filter" : res.action === "monitor" ? "monitor" : res.action === "ask" ? "askme" : "allow");
      const matchesStr = (res.matches || []).map(m => m.list + (m.category ? "(" + m.category + ")" : "") + " x" + m.count).join(", ");
      $("try-matches").textContent = matchesStr ? "Matches: " + matchesStr : "No matches";
      $("try-rewritten").textContent = res.text || "(empty)";
    } catch (e) { flash(e.message, true); }
  }, "Testing…"));

  $("content-json").addEventListener("input", () => { contentJsonDirty = true; });
  $("content-json-reload").addEventListener("click", () => { contentJsonDirty = false; refreshContent(); });
  $("content-json-save").addEventListener("click", busy(async () => {
    try {
      const parsed = JSON.parse($("content-json").value);
      await api("PUT", "/api/content", { rules: parsed, note: $("content-json-note").value });
      cancelEditList();
      contentJsonDirty = false;
      $("content-json-note").value = "";
      flash("Content rules saved from JSON.");
      await refreshContent();
    } catch (e) { flash(e.message, true); }
  }, "Saving…"));

  api("GET", "/api/state").then(showApp, showLogin);
})();
