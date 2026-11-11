// GuardFil Playground Client Logic (Advisory Developer Tool)

document.addEventListener("DOMContentLoaded", function () {
  var activeTab = "tab-evaluate";
  var catalogTools = [];
  var lastHistoryResults = [];

  var toolSelect = document.getElementById("tool-select");
  var customToolGroup = document.getElementById("custom-tool-group");
  var customToolInput = document.getElementById("custom-tool-input");
  var credentialSelect = document.getElementById("credential-select");
  var ttlInput = document.getElementById("ttl-input");
  var cancelledCheck = document.getElementById("cancelled-check");
  var expiredEnvelopeCheck = document.getElementById("expired-envelope-check");
  var payloadInput = document.getElementById("payload-input");
  var evalForm = document.getElementById("eval-form");

  var resultPlaceholder = document.getElementById("result-placeholder");
  var resultCard = document.getElementById("result-card");
  var badgeEffect = document.getElementById("badge-effect");
  var resultSummary = document.getElementById("result-summary");
  var traceStepsContainer = document.getElementById("trace-steps");
  var decisionFieldsTbody = document.getElementById("decision-fields");
  var reasonsSection = document.getElementById("reasons-section");
  var reasonsList = document.getElementById("reasons-list");
  var envelopeSection = document.getElementById("envelope-section");
  var envelopePre = document.getElementById("envelope-pre");

  var policySource = document.getElementById("policy-source");
  var policyDigest = document.getElementById("policy-digest");
  var policyRevision = document.getElementById("policy-revision");
  var policyToolSet = document.getElementById("policy-tool-set");
  var policyError = document.getElementById("policy-error");
  var policyApplyBtn = document.getElementById("policy-apply-btn");
  var policyResetBtn = document.getElementById("policy-reset-btn");

  var runFixturesBtn = document.getElementById("run-fixtures-btn");
  var fixturesSummary = document.getElementById("fixtures-summary");
  var fixturesTbody = document.getElementById("fixtures-tbody");

  var historyTbody = document.getElementById("history-tbody");
  var countersPre = document.getElementById("counters-pre");
  var errorBanner = document.getElementById("error-banner");

  function showError(msg) {
    if (errorBanner) {
      errorBanner.textContent = msg;
      errorBanner.classList.remove("hidden");
    }
  }

  function clearError() {
    if (errorBanner) {
      errorBanner.textContent = "";
      errorBanner.classList.add("hidden");
    }
  }

  function showPolicyError(msg) {
    if (policyError) {
      var digest = (policyDigest && policyDigest.textContent) ? policyDigest.textContent : "";
      var shortDigest = digest.length >= 19 ? digest.slice(0, 19) : digest;
      policyError.textContent = msg + " - the previous policy (digest " + shortDigest + "...) stays active";
      policyError.classList.remove("hidden");
    }
  }

  function clearPolicyError() {
    if (policyError) {
      policyError.textContent = "";
      policyError.classList.add("hidden");
    }
  }

  function extractErrorMessage(response) {
    return response.json().then(
      function (data) {
        if (data && data.error) {
          return data.error;
        }
        return "HTTP " + response.status;
      },
      function () {
        return "HTTP " + response.status;
      }
    );
  }

  // Navigation tab switching
  var tabButtons = [
    { btn: document.getElementById("tab-evaluate-btn"), target: "tab-evaluate" },
    { btn: document.getElementById("tab-policy-btn"), target: "tab-policy" },
    { btn: document.getElementById("tab-fixtures-btn"), target: "tab-fixtures" },
    { btn: document.getElementById("tab-history-btn"), target: "tab-history" }
  ];

  function switchTab(targetId) {
    activeTab = targetId;
    for (var i = 0; i < tabButtons.length; i++) {
      var item = tabButtons[i];
      var isTarget = item.target === targetId;
      item.btn.setAttribute("aria-selected", isTarget ? "true" : "false");
      if (isTarget) {
        item.btn.classList.add("active");
      } else {
        item.btn.classList.remove("active");
      }
      var panel = document.getElementById(item.target);
      if (panel) {
        if (isTarget) {
          panel.classList.add("active");
        } else {
          panel.classList.remove("active");
        }
      }
    }
    if (targetId === "tab-history") {
      fetchState();
    }
  }

  for (var i = 0; i < tabButtons.length; i++) {
    (function (item) {
      item.btn.addEventListener("click", function () {
        switchTab(item.target);
      });
    })(tabButtons[i]);
  }

  // Pre-fill payload helper
  function getDefaultPayloadForTool(toolName) {
    if (toolName === "fake.read_note") {
      return '{\n  "note_id": "synthetic-note-001"\n}';
    }
    if (toolName === "fake.delete_record") {
      return '{\n  "record_id": "synthetic-record-001"\n}';
    }
    if (toolName === "fake.send_message") {
      return '{\n  "body": "synthetic body",\n  "recipient": "synthetic-recipient"\n}';
    }
    if (toolName === "fake.numeric_note") {
      return '{\n  "note_id": 123\n}';
    }
    return "{}";
  }

  toolSelect.addEventListener("change", function () {
    if (toolSelect.value === "__custom__") {
      customToolGroup.classList.remove("hidden");
      customToolInput.focus();
    } else {
      customToolGroup.classList.add("hidden");
      payloadInput.value = getDefaultPayloadForTool(toolSelect.value);
    }
  });

  // Presets
  document.getElementById("preset-allow-read").addEventListener("click", function () {
    toolSelect.value = "fake.read_note";
    customToolGroup.classList.add("hidden");
    payloadInput.value = getDefaultPayloadForTool("fake.read_note");
    credentialSelect.value = "valid";
    ttlInput.value = "30000";
    cancelledCheck.checked = false;
    expiredEnvelopeCheck.checked = false;
  });

  document.getElementById("preset-deny-delete").addEventListener("click", function () {
    toolSelect.value = "fake.delete_record";
    customToolGroup.classList.add("hidden");
    payloadInput.value = getDefaultPayloadForTool("fake.delete_record");
    credentialSelect.value = "valid";
    ttlInput.value = "30000";
    cancelledCheck.checked = false;
    expiredEnvelopeCheck.checked = false;
  });

  document.getElementById("preset-no-cred").addEventListener("click", function () {
    toolSelect.value = "fake.read_note";
    customToolGroup.classList.add("hidden");
    payloadInput.value = getDefaultPayloadForTool("fake.read_note");
    credentialSelect.value = "none";
    ttlInput.value = "30000";
    cancelledCheck.checked = false;
    expiredEnvelopeCheck.checked = false;
  });

  document.getElementById("preset-malformed").addEventListener("click", function () {
    toolSelect.value = "fake.read_note";
    customToolGroup.classList.add("hidden");
    payloadInput.value = '{"note_id":';
    credentialSelect.value = "valid";
    ttlInput.value = "30000";
    cancelledCheck.checked = false;
    expiredEnvelopeCheck.checked = false;
  });

  document.getElementById("preset-unknown-tool").addEventListener("click", function () {
    toolSelect.value = "__custom__";
    customToolGroup.classList.remove("hidden");
    customToolInput.value = "fake.unknown_tool";
    payloadInput.value = "{}";
    credentialSelect.value = "valid";
    ttlInput.value = "30000";
    cancelledCheck.checked = false;
    expiredEnvelopeCheck.checked = false;
  });

  document.getElementById("preset-expired-env").addEventListener("click", function () {
    toolSelect.value = "fake.read_note";
    customToolGroup.classList.add("hidden");
    payloadInput.value = getDefaultPayloadForTool("fake.read_note");
    credentialSelect.value = "valid";
    ttlInput.value = "30000";
    cancelledCheck.checked = false;
    expiredEnvelopeCheck.checked = true;
  });

  function renderResult(res) {
    resultPlaceholder.classList.add("hidden");
    resultCard.classList.remove("hidden");

    // Badge
    badgeEffect.className = "badge";
    if (res.effect === "ALLOW") {
      badgeEffect.classList.add("badge-allow");
      badgeEffect.textContent = "ALLOW";
    } else {
      badgeEffect.classList.add("badge-block");
      badgeEffect.textContent = "BLOCK";
    }

    var summaryText = res.code || "";
    if (res.stage) {
      summaryText += " (" + res.stage + ")";
    }
    resultSummary.textContent = summaryText;

    // Trace
    while (traceStepsContainer.firstChild) {
      traceStepsContainer.removeChild(traceStepsContainer.firstChild);
    }
    if (res.trace && res.trace.length > 0) {
      for (var i = 0; i < res.trace.length; i++) {
        var step = res.trace[i];
        var stepDiv = document.createElement("div");
        stepDiv.className = "trace-step status-" + step.status;

        var nameSpan = document.createElement("span");
        nameSpan.className = "trace-step-name";
        nameSpan.textContent = step.step;
        stepDiv.appendChild(nameSpan);

        var statusSpan = document.createElement("span");
        statusSpan.className = "trace-step-status";
        var statusLabel = step.status;
        if (step.code) {
          statusLabel += ": " + step.code;
        }
        statusSpan.textContent = statusLabel;
        stepDiv.appendChild(statusSpan);

        traceStepsContainer.appendChild(stepDiv);
      }
    }

    // Key-value decision details
    while (decisionFieldsTbody.firstChild) {
      decisionFieldsTbody.removeChild(decisionFieldsTbody.firstChild);
    }

    var fields = [
      { key: "synthetic", val: String(res.synthetic) },
      { key: "request_id", val: res.request_id },
      { key: "tool", val: res.tool },
      { key: "fake_tool_known", val: String(res.fake_tool_known) },
      { key: "effect", val: res.effect },
      { key: "code", val: res.code },
      { key: "stage", val: res.stage || "-" },
      { key: "dispatch_eligible", val: String(res.dispatch_eligible) },
      { key: "action_id", val: res.action_id || "-" },
      { key: "decision_id", val: res.decision_id || "-" },
      { key: "action_digest", val: res.action_digest || "-" },
      { key: "tool_revision", val: res.tool_revision || "-" },
      { key: "boundary", val: res.boundary || "-" },
      { key: "revocation_epoch", val: String(res.revocation_epoch) },
      { key: "policy_digest", val: res.policy_digest || "-" },
      { key: "policy_revision", val: String(res.policy_revision) },
      { key: "evaluated_at", val: res.evaluated_at || "-" },
      { key: "expires_at", val: res.expires_at || "-" },
      { key: "received_at", val: res.received_at || "-" },
      { key: "deadline_at", val: res.deadline_at || "-" }
    ];

    for (var f = 0; f < fields.length; f++) {
      var tr = document.createElement("tr");
      var tdKey = document.createElement("td");
      tdKey.className = "key";
      tdKey.textContent = fields[f].key;
      tr.appendChild(tdKey);

      var tdVal = document.createElement("td");
      tdVal.className = "val";
      tdVal.textContent = fields[f].val;
      tr.appendChild(tdVal);

      decisionFieldsTbody.appendChild(tr);
    }

    // Reasons
    while (reasonsList.firstChild) {
      reasonsList.removeChild(reasonsList.firstChild);
    }
    if (res.reasons && res.reasons.length > 0) {
      reasonsSection.classList.remove("hidden");
      for (var r = 0; r < res.reasons.length; r++) {
        var reason = res.reasons[r];
        var li = document.createElement("li");
        var rText = reason.code || "";
        if (reason.rule_id) {
          rText += " (rule: " + reason.rule_id + ")";
        }
        li.textContent = rText;
        reasonsList.appendChild(li);
      }
    } else {
      reasonsSection.classList.add("hidden");
    }

    // Error envelope
    if (res.effect === "BLOCK" && res.error_envelope) {
      envelopeSection.classList.remove("hidden");
      envelopePre.textContent = JSON.stringify(res.error_envelope, null, 2);
    } else {
      envelopeSection.classList.add("hidden");
      envelopePre.textContent = "";
    }
  }

  function uint8ArrayToBase64(bytes) {
    var binary = "";
    var len = bytes.byteLength;
    var chunkSize = 0x8000;
    for (var i = 0; i < len; i += chunkSize) {
      var chunk = bytes.subarray(i, Math.min(i + chunkSize, len));
      binary += String.fromCharCode.apply(null, chunk);
    }
    return btoa(binary);
  }

  // Handle evaluation submission
  evalForm.addEventListener("submit", function (e) {
    e.preventDefault();

    var tool = toolSelect.value;
    if (tool === "__custom__") {
      tool = customToolInput.value;
    }

    // Send payload value as-is without trimming, base64 encoded via TextEncoder
    var payloadRaw = payloadInput.value;
    var payloadBytes = new TextEncoder().encode(payloadRaw);
    var payloadB64 = uint8ArrayToBase64(payloadBytes);
    var ttl = parseInt(ttlInput.value, 10);
    if (isNaN(ttl)) {
      ttl = 30000;
    }

    var payloadObj = {
      tool: tool,
      payload_b64: payloadB64,
      credential: credentialSelect.value,
      ttl_ms: ttl,
      cancelled: cancelledCheck.checked,
      expired_envelope: expiredEnvelopeCheck.checked
    };

    fetch("/api/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payloadObj)
    })
      .then(function (response) {
        if (!response.ok) {
          return extractErrorMessage(response).then(function (msg) {
            showError(msg);
          });
        }
        clearError();
        return response.json().then(function (data) {
          renderResult(data);
          fetchState();
        });
      })
      .catch(function (err) {
        showError("Request error: " + err);
      });
  });

  // Policy tab actions
  policyApplyBtn.addEventListener("click", function () {
    fetch("/api/policy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source: policySource.value })
    })
      .then(function (response) {
        if (!response.ok) {
          return extractErrorMessage(response).then(function (msg) {
            showPolicyError(msg);
          });
        }
        clearPolicyError();
        return response.json().then(function (info) {
          policyDigest.textContent = info.digest;
          policyRevision.textContent = String(info.revision);
        });
      })
      .catch(function (err) {
        showPolicyError("Network error: " + err);
      });
  });

  policyResetBtn.addEventListener("click", function () {
    fetch("/api/policy/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    })
      .then(function (response) {
        if (!response.ok) {
          return extractErrorMessage(response).then(function (msg) {
            showPolicyError(msg);
          });
        }
        clearPolicyError();
        return response.json().then(function (info) {
          policySource.value = info.source;
          policyDigest.textContent = info.digest;
          policyRevision.textContent = String(info.revision);
        });
      })
      .catch(function (err) {
        showPolicyError("Network error: " + err);
      });
  });

  // Run fixtures
  runFixturesBtn.addEventListener("click", function () {
    fixturesSummary.classList.add("hidden");
    fixturesSummary.textContent = "";

    fetch("/api/fixtures", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    })
      .then(function (response) {
        if (!response.ok) {
          return extractErrorMessage(response).then(function (msg) {
            showError(msg);
          });
        }
        clearError();
        return response.json().then(function (rows) {
          while (fixturesTbody.firstChild) {
            fixturesTbody.removeChild(fixturesTbody.firstChild);
          }

          var allowCount = 0;
          var blockCount = 0;
          var dispatchEligibleCount = 0;
          for (var i = 0; i < rows.length; i++) {
            var row = rows[i];
            if (row.effect === "ALLOW") {
              allowCount++;
            } else if (row.effect === "BLOCK") {
              blockCount++;
            }
            if (row.dispatch_eligible) {
              dispatchEligibleCount++;
            }
          }

          fixturesSummary.classList.remove("hidden");
          fixturesSummary.textContent = rows.length + " fixtures: " + allowCount + " ALLOW, " + blockCount + " BLOCK; dispatch_eligible=true on " + dispatchEligibleCount;

          for (var i = 0; i < rows.length; i++) {
            var row = rows[i];
            var tr = document.createElement("tr");

            var tdId = document.createElement("td");
            tdId.textContent = row.fixture_id;
            tr.appendChild(tdId);

            var tdTool = document.createElement("td");
            tdTool.textContent = row.tool;
            tr.appendChild(tdTool);

            var tdEffect = document.createElement("td");
            tdEffect.textContent = row.effect;
            tr.appendChild(tdEffect);

            var tdStage = document.createElement("td");
            tdStage.textContent = row.stage;
            tr.appendChild(tdStage);

            var tdAuth = document.createElement("td");
            tdAuth.textContent = row.auth;
            tr.appendChild(tdAuth);

            var tdReason = document.createElement("td");
            tdReason.textContent = row.reason;
            tr.appendChild(tdReason);

            var tdDigest = document.createElement("td");
            tdDigest.className = "cell-digest";
            tdDigest.textContent = row.action_digest || "-";
            tr.appendChild(tdDigest);

            var tdEligible = document.createElement("td");
            tdEligible.textContent = String(row.dispatch_eligible);
            tr.appendChild(tdEligible);

            fixturesTbody.appendChild(tr);
          }
        });
      })
      .catch(function (err) {
        showError("Error running fixtures: " + err);
      });
  });

  // State fetch & update
  function fetchState() {
    fetch("/api/state")
      .then(function (response) {
        if (!response.ok) {
          return extractErrorMessage(response).then(function (msg) {
            showError(msg);
          });
        }
        clearError();
        return response.json().then(function (state) {
          // Update Policy meta
          if (state.policy) {
            if (!policySource.value) {
              policySource.value = state.policy.source;
            }
            policyDigest.textContent = state.policy.digest;
            policyRevision.textContent = String(state.policy.revision);
          }
          if (state.tool_set && policyToolSet) {
            policyToolSet.textContent = state.tool_set;
          }

          // Update Tools catalog dropdown if not already populated
          if (state.tools && catalogTools.length === 0) {
            catalogTools = state.tools;
            while (toolSelect.firstChild) {
              toolSelect.removeChild(toolSelect.firstChild);
            }
            for (var t = 0; t < state.tools.length; t++) {
              var toolItem = state.tools[t];
              var opt = document.createElement("option");
              opt.value = toolItem.tool;
              opt.textContent = toolItem.tool + (toolItem.in_registry ? " (registered)" : " (catalog only)");
              toolSelect.appendChild(opt);
            }
            var customOpt = document.createElement("option");
            customOpt.value = "__custom__";
            customOpt.textContent = "-- Custom Tool Name --";
            toolSelect.appendChild(customOpt);

            payloadInput.value = getDefaultPayloadForTool(toolSelect.value);
          }

          // Update Counters
          if (state.counters_text) {
            countersPre.textContent = state.counters_text;
          }

          // Update History
          if (state.history) {
            lastHistoryResults = state.history;
            while (historyTbody.firstChild) {
              historyTbody.removeChild(historyTbody.firstChild);
            }
            for (var h = 0; h < state.history.length; h++) {
              (function (item) {
                var htr = document.createElement("tr");
                htr.className = "clickable";

                var tdTime = document.createElement("td");
                tdTime.textContent = item.evaluated_at || item.received_at || item.request_id;
                htr.appendChild(tdTime);

                var tdTool = document.createElement("td");
                tdTool.textContent = item.tool;
                htr.appendChild(tdTool);

                var tdCred = document.createElement("td");
                tdCred.textContent = item.credential || "-";
                htr.appendChild(tdCred);

                var tdEff = document.createElement("td");
                tdEff.textContent = item.effect;
                htr.appendChild(tdEff);

                var tdCode = document.createElement("td");
                tdCode.textContent = item.code;
                htr.appendChild(tdCode);

                htr.addEventListener("click", function () {
                  renderResult(item);
                  switchTab("tab-evaluate");
                });

                historyTbody.appendChild(htr);
              })(state.history[h]);
            }
          }
        });
      })
      .catch(function (err) {
        showError("State fetch error: " + err);
      });
  }

  fetchState();
});
