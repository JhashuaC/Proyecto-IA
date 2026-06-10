const metrics = window.__METRICS__ || {};
const result = window.__RESULT__;
const indicators = window.__INDICATORS__ || [];

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

const metricLabels = [
  ["total", "Ejemplos"],
  ["accuracy", "Exactitud"],
  ["tp", "Verd. positivos"],
  ["tn", "Verd. negativos"],
  ["fp", "Falsos positivos"],
  ["fn", "Falsos negativos"],
];

function renderMetrics() {
  const target = document.querySelector("#metrics-grid");
  if (!target) return;
  target.innerHTML = metricLabels.map(([key, label]) => {
    const suffix = key === "accuracy" ? "%" : "";
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
          <h2>Tu resultado aparecera aqui</h2>
          <p>Carga un archivo .eml o pega el contenido del correo y presiona Analizar riesgo. El panel se actualizara automaticamente.</p>
        </div>
      `;
    }
    return;
  }

  const level = result.level.toLowerCase();
  const guidance = {
    alto: {
      title: "No confies en este correo",
      body: "No abras enlaces ni adjuntos. Reportalo al area de TI o elimina el mensaje si era una prueba.",
    },
    medio: {
      title: "Revisalo con cuidado",
      body: "Verifica el remitente por otro canal antes de responder, descargar archivos o iniciar sesion.",
    },
    bajo: {
      title: "Parece seguro",
      body: "No se detectaron senales criticas, pero confirma siempre que el remitente y el contexto tengan sentido.",
    },
  }[level] || {
    title: "Resultado calculado",
    body: "Revisa las senales tecnicas para tomar una decision.",
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
    ? attachments.map((item) => `<li>${escapeHtml(item.filename)} <span>${escapeHtml(item.content_type)}, ${escapeHtml(item.size)} bytes</span></li>`).join("")
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
        <p>${escapeHtml(result.level)} riesgo detectado con explicacion de tecnicas combinadas.</p>
      </div>
      <div class="risk-orbit" style="--risk:${result.final_score}">
        <span>${escapeHtml(result.final_score)}%</span>
      </div>
    </div>
    <div class="risk-bar"><span style="width:${result.final_score}%"></span></div>
    <div class="friendly-verdict">
      <strong>${escapeHtml(guidance.title)}</strong>
      <p>${escapeHtml(guidance.body)}</p>
    </div>
    <div class="tech-grid">${techniques}</div>
    <div class="summary-grid">${summaryCards}</div>
    <div class="match-grid">${matchHtml}</div>
    <div class="reason-box">
      <h3>Senales encontradas</h3>
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

renderMetrics();
renderResult();
renderIndicators();

document.querySelectorAll(".analysis-form").forEach((form) => {
  form.addEventListener("submit", () => {
    const button = form.querySelector("button[type='submit']");
    if (button) {
      button.disabled = true;
      button.textContent = "Analizando...";
    }
  });
});
