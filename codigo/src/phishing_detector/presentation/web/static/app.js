const metrics = window.__METRICS__ || {};
const result = window.__RESULT__;
const indicators = window.__INDICATORS__ || [];
const historyRows = window.__HISTORY__ || [];

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function decodeMimeWords(value) {
  return String(value || "").replace(/=\?([^?]+)\?([bqBQ])\?([^?]+)\?=/g, (_, charset, encoding, payload) => {
    try {
      if (encoding.toLowerCase() === "b") {
        const binary = atob(payload);
        const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
        return new TextDecoder(charset || "utf-8").decode(bytes);
      }
      const qp = payload.replaceAll("_", " ").replace(/=([0-9A-F]{2})/gi, "%$1");
      return decodeURIComponent(qp);
    } catch {
      return payload;
    }
  });
}

function decodeQuotedPrintable(value) {
  const prepared = String(value || "")
    .replace(/=\r?\n/g, "")
    .replace(/=([0-9A-F]{2})/gi, "%$1");
  try {
    return decodeURIComponent(prepared);
  } catch {
    return String(value || "").replace(/=\r?\n/g, "");
  }
}

function parseEmlPreview(raw) {
  const normalized = raw.replace(/\r\n/g, "\n");
  const splitAt = normalized.search(/\n\n/);
  const headerText = splitAt >= 0 ? normalized.slice(0, splitAt) : normalized;
  const bodyText = splitAt >= 0 ? normalized.slice(splitAt + 2) : "";
  const headers = {};
  let current = "";

  headerText.split("\n").forEach((line) => {
    if (/^\s/.test(line) && current) {
      headers[current] = `${headers[current]} ${line.trim()}`.trim();
      return;
    }
    const index = line.indexOf(":");
    if (index > 0) {
      current = line.slice(0, index).trim().toLowerCase();
      headers[current] = line.slice(index + 1).trim();
    }
  });

  const cleanBody = decodeQuotedPrintable(bodyText)
    .replace(/^Content-[^\n]+$/gim, "")
    .replace(/^--[^\n]+$/gim, "")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  const links = Array.from(new Set((raw.match(/https?:\/\/[^\s<>"')]+/g) || []).map((link) => link.replace(/[.,);]+$/, ""))));
  const emailAddress = (value) => {
    const match = String(value || "").match(/<([^>]+)>/);
    return match ? match[1] : String(value || "").trim();
  };

  return {
    subject: decodeMimeWords(headers.subject || ""),
    sender: emailAddress(decodeMimeWords(headers.from || "")),
    reply_to: emailAddress(decodeMimeWords(headers["reply-to"] || "")),
    return_path: emailAddress(decodeMimeWords(headers["return-path"] || "")),
    authentication_results: decodeMimeWords(headers["authentication-results"] || ""),
    url: links[0] || "",
    body: cleanBody,
  };
}

function setField(id, value) {
  const field = document.querySelector(`#${id}`);
  if (field) field.value = value || "";
}

function fillFieldsFromEml(file, status) {
  const reader = new FileReader();
  reader.addEventListener("load", () => {
    const data = parseEmlPreview(String(reader.result || ""));
    setField("subject", data.subject);
    setField("url", data.url);
    setField("body", data.body);
    setField("sender", data.sender);
    setField("reply_to", data.reply_to);
    setField("return_path", data.return_path);
    setField("authentication_results", data.authentication_results);
    if (status) {
      status.textContent = `Archivo listo y campos actualizados: ${file.name}`;
    }
  });
  reader.addEventListener("error", () => {
    if (status) {
      status.textContent = `Archivo seleccionado, pero no se pudo previsualizar: ${file.name}`;
    }
  });
  reader.readAsText(file, "utf-8");
}

const metricLabels = [
  ["train_total", "Entrenamiento"],
  ["test_total", "Prueba"],
  ["train_accuracy", "Exactitud entrenamiento"],
  ["test_accuracy", "Exactitud prueba"],
  ["external_examples", "Ejemplos externos"],
  ["tp", "Verd. positivos"],
  ["tn", "Verd. negativos"],
  ["fp", "Falsos positivos"],
  ["fn", "Falsos negativos"],
];

function renderMetrics() {
  const target = document.querySelector("#metrics-grid");
  if (!target) return;
  target.innerHTML = metricLabels.map(([key, label]) => {
    const suffix = key.includes("accuracy") ? "%" : "";
    return `<article class="metric-card"><span>${escapeHtml(label)}</span><strong>${escapeHtml(metrics[key])}${suffix}</strong></article>`;
  }).join("");

  const lossLine = document.querySelector("#loss-line");
  const loss = metrics.loss || [];
  if (lossLine && loss.length > 0) {
    const max = Math.max(...loss);
    lossLine.innerHTML = loss.map((value, index) => {
      const height = Math.max(8, 48 - (value / max) * 32);
      return `<i style="height:${height}px; animation-delay:${index * 70}ms"></i>`;
    }).join("");
  }
}

function renderResult() {
  const panel = document.querySelector("#result-panel");
  if (!panel || !result) {
    if (panel) {
      panel.classList.add("empty");
      panel.innerHTML = `
        <div class="empty-state">
          <span>Listo para analizar</span>
          <h2>Tu resultado aparecerá aquí</h2>
          <p>Carga un archivo .eml o pega el contenido del correo y presiona Analizar riesgo. El panel se actualizará automáticamente.</p>
        </div>
      `;
    }
    return;
  }

  const level = result.level.toLowerCase();
  const guidance = {
    alto: {
      title: "No confíes en este correo",
      body: "No abras enlaces ni adjuntos. Repórtalo al área de TI o elimina el mensaje si era una prueba.",
    },
    medio: {
      title: "Revísalo con cuidado",
      body: "Verifica el remitente por otro canal antes de responder, descargar archivos o iniciar sesión.",
    },
    bajo: {
      title: "Parece seguro",
      body: "No se detectaron señales críticas, pero confirma siempre que el remitente y el contexto tengan sentido.",
    },
  }[level] || {
    title: "Resultado calculado",
    body: "Revisa las señales técnicas para tomar una decisión.",
  };
  const techniques = result.technique_scores.map((item) => `
    <article class="tech-card">
      <div class="score-ring" style="--score:${item.score}">
        <span>${escapeHtml(item.score)}%</span>
      </div>
      <div>
        <strong>${escapeHtml(item.name)}</strong>
        <p>${escapeHtml(item.details)}</p>
      </div>
    </article>
  `).join("");

  const reasons = result.reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("");
  const summary = result.email_summary || {};
  const attachments = summary.attachments || [];
  const matches = result.indicator_matches || [];
  const summaryCards = [
    ["Origen", summary.source_name || "manual"],
    ["From", summary.sender || "No detectado"],
    ["Reply-To", summary.reply_to || "No detectado"],
    ["Return-Path", summary.return_path || "No detectado"],
    ["Enlaces", summary.link_count ?? 0],
    ["Adjuntos", summary.attachment_count ?? 0],
    ["Cabeceras", summary.headers_analyzed ?? 0],
    ["Auth-Results", summary.auth_present ? "Presente" : "Ausente"],
  ].map(([label, value]) => `<article class="summary-card"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></article>`).join("");

  const attachmentHtml = attachments.length
    ? attachments.map((item) => {
        const notes = (item.risk_notes || []).length ? item.risk_notes.join(" ") : "Sin señales internas.";
        const flags = [
          item.has_double_extension ? "doble extensión" : "",
          item.macro_suspected ? "macros sospechosas" : "",
          item.extension ? `extensión .${item.extension}` : "",
        ].filter(Boolean).join(", ");
        const hash = item.sha256 ? `<span>SHA-256: ${escapeHtml(item.sha256)}</span>` : "";
        return `<li>${escapeHtml(item.filename)} <span>${escapeHtml(item.content_type)}, ${escapeHtml(item.size)} bytes${flags ? `, ${escapeHtml(flags)}` : ""}</span><span>${escapeHtml(notes)}</span>${hash}</li>`;
      }).join("")
    : "<li>No se detectaron adjuntos.</li>";

  const matchHtml = matches.length
    ? matches.map((item) => `
        <article class="match-card">
          <span>${escapeHtml(item.category)}</span>
          <strong>${escapeHtml(item.name)}</strong>
          <p>${escapeHtml(item.evidence)}</p>
        </article>
      `).join("")
    : `<article class="match-card"><span>Indicadores</span><strong>Sin coincidencias personalizadas</strong><p>No se activaron indicadores adicionales.</p></article>`;

  panel.classList.add("active", level);
  panel.innerHTML = `
    <div class="result-summary">
      <div>
        <p class="eyebrow">Resultado</p>
        <h2>${escapeHtml(result.decision)}</h2>
        <p>${escapeHtml(result.level)} riesgo detectado con explicación de técnicas combinadas.</p>
      </div>
      <div class="risk-orbit" style="--risk:${result.final_score}">
        <span>${escapeHtml(result.final_score)}%</span>
      </div>
    </div>
    <div class="risk-bar"><span style="width:${result.final_score}%"></span></div>
    <div class="friendly-verdict">
      <strong>${escapeHtml(guidance.title)}</strong>
      <p>${escapeHtml(guidance.body)}</p>
      ${result.report_url ? `<a class="report-link" href="${escapeHtml(result.report_url)}" target="_blank" rel="noopener">Abrir reporte PDF</a>` : ""}
    </div>
    <div class="tech-grid">${techniques}</div>
    <div class="summary-grid">${summaryCards}</div>
    <div class="match-grid">${matchHtml}</div>
    <div class="reason-box">
      <h3>Señales encontradas</h3>
      <ul>${reasons}</ul>
    </div>
    <div class="reason-box">
      <h3>Adjuntos</h3>
      <ul>${attachmentHtml}</ul>
    </div>
  `;

  const shouldFocusResult = window.location.hash === "#result-panel" || result.final_score !== undefined;
  if (shouldFocusResult) {
    window.requestAnimationFrame(() => {
      panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
    });
  }
}

function renderTreeNode(node) {
  if (!node) return "";
  const visited = node.visited ? " visited" : " muted";
  if (node.leaf) {
    return `<li class="tree-node${visited}"><details open><summary><strong>${escapeHtml(node.label)}</strong> <span>${escapeHtml(node.probability)}% phishing</span></summary></details></li>`;
  }
  return `
    <li class="tree-node${visited}">
      <details ${node.visited ? "open" : ""}>
        <summary>${escapeHtml(node.feature)} &lt; ${escapeHtml(node.threshold)} <span>${escapeHtml(node.probability)}%</span></summary>
        <ul>
          <li class="branch-label">Sí ${renderTreeNode(node.left)}</li>
          <li class="branch-label">No ${renderTreeNode(node.right)}</li>
        </ul>
      </details>
    </li>
  `;
}

function renderXai() {
  const target = document.querySelector("#xai-content");
  if (!target) return;
  if (!result || !result.explanations) {
    target.innerHTML = `<div class="empty-state compact"><span>Sin análisis</span><p>Ejecuta un análisis para ver el proceso interno de cada técnica.</p></div>`;
    return;
  }

  const xai = result.explanations;
  const tree = xai.decision_tree || {};
  const bayes = xai.naive_bayes || {};
  const expert = xai.expert_system || {};
  const neural = xai.neural_network || {};
  const comparison = xai.comparison || [];
  const tabs = [
    ["tree", "Árbol"],
    ["bayes", "Naive Bayes"],
    ["expert", "Sistema experto"],
    ["neural", "Red neuronal"],
    ["compare", "Comparación"],
  ];

  const treeSteps = (tree.path || []).map((step) => `
    <article class="timeline-item">
      <span>Paso ${escapeHtml(step.step)}</span>
      <strong>${escapeHtml(step.condition)}</strong>
      <p>Valor: ${escapeHtml(step.value)}. Resultado: ${escapeHtml(step.decision)}. Rama: ${escapeHtml(step.branch)}.</p>
    </article>
  `).join("");

  const bayesRows = (bayes.conditionals || []).map((row) => `
    <tr>
      <td>${escapeHtml(row.token)}</td>
      <td>${escapeHtml(row.classes?.Phishing?.conditional_probability ?? "")}</td>
      <td>${escapeHtml(row.classes?.Seguro?.conditional_probability ?? "")}</td>
      <td>${escapeHtml(row.classes?.Phishing?.log_probability ?? "")}</td>
      <td>${escapeHtml(row.classes?.Seguro?.log_probability ?? "")}</td>
    </tr>
  `).join("");

  const ruleCards = (expert.rules || []).map((rule) => `
    <article class="rule-card ${rule.active ? "active" : "inactive"}">
      <span>Regla ${escapeHtml(rule.id)} - ${escapeHtml(rule.state)}</span>
      <strong>${escapeHtml(rule.name)}</strong>
      <p>${escapeHtml(rule.rule)}</p>
      <p>${escapeHtml(rule.active ? rule.evidence : rule.discard_reason)}</p>
      <b>+${escapeHtml(rule.active ? rule.weight : 0)} | parcial ${escapeHtml(rule.partial_score)}</b>
    </article>
  `).join("");

  const neuronBars = (neural.hidden_neurons || []).map((neuron) => `
    <article class="neuron" title="Suma ponderada: ${escapeHtml(neuron.weighted_sum)} | Peso salida: ${escapeHtml(neuron.outgoing_weight)}">
      <span>N${escapeHtml(neuron.index + 1)}</span>
      <i style="height:${Math.max(8, Number(neuron.activation_percent || 0) * 0.7)}px"></i>
      <strong>${escapeHtml(neuron.activation_percent)}%</strong>
    </article>
  `).join("");

  const inputRows = (neural.top_inputs || []).map((item) => `
    <li><strong>${escapeHtml(item.name)}</strong><span>${escapeHtml(item.value)}</span></li>
  `).join("");

  const comparisonRows = comparison.map((row) => `
    <tr>
      <td>${escapeHtml(row.model)}</td>
      <td>${escapeHtml(row.result)}</td>
      <td>${escapeHtml(row.confidence)}%</td>
      <td>${escapeHtml(row.time_ms)} ms</td>
      <td>${escapeHtml((row.influential_variables || []).join(", "))}</td>
      <td>${escapeHtml(row.summary)}</td>
    </tr>
  `).join("");

  target.innerHTML = `
    <div class="xai-tabs" role="tablist">
      ${tabs.map(([id, label], index) => `<button type="button" class="xai-tab ${index === 0 ? "active" : ""}" data-xai-tab="${id}">${escapeHtml(label)}</button>`).join("")}
    </div>
    <div class="xai-view active" data-xai-view="tree">
      <div class="xai-grid">
        <div class="xai-card">
          <h3>Ruta recorrida</h3>
          <div class="timeline">${treeSteps || "<p>No hubo nodos intermedios.</p>"}</div>
          <div class="xai-final">Hoja final: ${escapeHtml(tree.leaf?.class || "")} (${escapeHtml(tree.leaf?.probability || 0)}%)</div>
        </div>
        <div class="xai-card">
          <h3>Árbol visual</h3>
          <ul class="decision-tree">${renderTreeNode(tree.tree)}</ul>
        </div>
      </div>
    </div>
    <div class="xai-view" data-xai-view="bayes">
      <div class="xai-card">
        <h3>Fórmula aplicada</h3>
        <p>${escapeHtml(bayes.formula || "")}</p>
        <div class="prob-grid">
          <article><span>P(Phishing)</span><strong>${escapeHtml(bayes.priors?.Phishing?.probability || 0)}</strong></article>
          <article><span>P(Seguro)</span><strong>${escapeHtml(bayes.priors?.Seguro?.probability || 0)}</strong></article>
          <article><span>Posterior phishing</span><strong>${escapeHtml(bayes.posteriors?.Phishing || 0)}%</strong></article>
          <article><span>Posterior seguro</span><strong>${escapeHtml(bayes.posteriors?.Seguro || 0)}%</strong></article>
        </div>
      </div>
      <details class="xai-card" open>
        <summary>Tabla de probabilidades condicionales</summary>
        <div class="table-scroll"><table><thead><tr><th>Token</th><th>P(token|phishing)</th><th>P(token|seguro)</th><th>log phishing</th><th>log seguro</th></tr></thead><tbody>${bayesRows}</tbody></table></div>
      </details>
    </div>
    <div class="xai-view" data-xai-view="expert">
      <div class="xai-card">
        <h3>Inferencia</h3>
        <p>${escapeHtml(expert.inference_type || "")}. ${escapeHtml(expert.textual_explanation || "")}</p>
        <div class="xai-final">Conclusión: ${escapeHtml(expert.final_class || "")} | puntaje ${escapeHtml(expert.final_score || 0)}</div>
      </div>
      <details class="xai-card" open>
        <summary>Reglas evaluadas</summary>
        <div class="rule-grid">${ruleCards}</div>
      </details>
    </div>
    <div class="xai-view" data-xai-view="neural">
      <div class="xai-grid">
        <div class="xai-card">
          <h3>Flujo de la red</h3>
          <p>${escapeHtml(neural.activation_function || "")}</p>
          <div class="network-diagram">
            <div><span>Entrada</span><strong>${escapeHtml(neural.layers?.[0]?.count || 0)}</strong></div>
            <div><span>Capa oculta</span><strong>${escapeHtml(neural.layers?.[1]?.count || 0)}</strong></div>
            <div><span>Salida</span><strong>${escapeHtml(neural.output?.probability_phishing || 0)}%</strong></div>
          </div>
          <ul class="feature-list">${inputRows}</ul>
        </div>
        <div class="xai-card">
          <h3>Activaciones de neuronas</h3>
          <div class="neuron-grid">${neuronBars}</div>
        </div>
      </div>
    </div>
    <div class="xai-view" data-xai-view="compare">
      <div class="xai-card">
        <h3>Comparación entre modelos</h3>
        <p>Votos phishing: ${escapeHtml(xai.agreement?.phishing_votes || 0)}. Votos seguro: ${escapeHtml(xai.agreement?.safe_votes || 0)}. Discrepancias: ${escapeHtml((xai.agreement?.discrepancies || []).join(", ") || "ninguna")}.</p>
        <div class="table-scroll"><table><thead><tr><th>Modelo</th><th>Resultado</th><th>Confianza</th><th>Tiempo</th><th>Variables influyentes</th><th>Resumen</th></tr></thead><tbody>${comparisonRows}</tbody></table></div>
      </div>
    </div>
  `;

  target.querySelectorAll(".xai-tab").forEach((button) => {
    button.addEventListener("click", () => {
      const id = button.dataset.xaiTab;
      target.querySelectorAll(".xai-tab").forEach((tab) => tab.classList.toggle("active", tab === button));
      target.querySelectorAll(".xai-view").forEach((view) => view.classList.toggle("active", view.dataset.xaiView === id));
    });
  });
}

function renderIndicators() {
  const list = document.querySelector("#indicator-list");
  if (!list) return;
  list.innerHTML = indicators.map((item) => `
    <article class="indicator-chip">
      <div>
        <span>${escapeHtml(item.category)}</span>
        <strong>${escapeHtml(item.name)}</strong>
      </div>
      <code>${escapeHtml(item.pattern)}</code>
      <b>+${escapeHtml(item.weight)}</b>
    </article>
  `).join("");
}

function renderHistory() {
  const list = document.querySelector("#history-list");
  if (!list) return;
  if (!historyRows.length) {
    list.innerHTML = `<article class="history-card"><strong>Sin análisis guardados</strong><p>Cuando analices un correo, aparecerá aquí con su reporte PDF.</p></article>`;
    return;
  }
  list.innerHTML = historyRows.slice(-8).reverse().map((item) => `
    <article class="history-card">
      <div>
        <span>${escapeHtml(item.timestamp)}</span>
        <strong>${escapeHtml(item.level)} - ${escapeHtml(item.final_score)}%</strong>
      </div>
      <p>${escapeHtml(item.subject || item.url || item.source_name || "Análisis sin asunto")}</p>
      ${item.report_url ? `<a href="${escapeHtml(item.report_url)}" target="_blank" rel="noopener">PDF</a>` : ""}
    </article>
  `).join("");
}

renderMetrics();
renderResult();
renderXai();
renderIndicators();
renderHistory();

document.querySelectorAll(".analysis-form").forEach((form) => {
  form.addEventListener("submit", () => {
    const button = form.querySelector("button[type='submit']");
    if (button) {
      button.disabled = true;
      button.textContent = "Analizando...";
    }
  });
});

document.querySelectorAll(".upload-zone").forEach((zone) => {
  const input = zone.querySelector("input[type='file']");
  if (!input) return;

  const status = document.createElement("div");
  status.className = "file-status";
  status.textContent = "Ningún archivo seleccionado";
  zone.appendChild(status);

  input.addEventListener("change", () => {
    const file = input.files && input.files[0];
    zone.classList.toggle("file-selected", Boolean(file));
    status.textContent = file ? `Archivo listo: ${file.name}` : "Ningún archivo seleccionado";
    if (file) {
      fillFieldsFromEml(file, status);
    }
  });

  ["dragenter", "dragover"].forEach((eventName) => {
    zone.addEventListener(eventName, (event) => {
      event.preventDefault();
      zone.classList.add("drag-over");
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    zone.addEventListener(eventName, () => {
      zone.classList.remove("drag-over");
    });
  });
});
