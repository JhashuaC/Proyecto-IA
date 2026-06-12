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
