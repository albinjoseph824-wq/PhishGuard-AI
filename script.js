document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("urlInput");
  const scanBtn = document.getElementById("scanBtn");
  const result = document.getElementById("result");
  const label = document.getElementById("label");
  const domain = document.getElementById("domain");
  const scoreEl = document.getElementById("score");
  const meterFill = document.getElementById("meterFill");
  const findingsList = document.getElementById("findingsList");
  const explanation = document.getElementById("explanation");
  const riskBadge = document.getElementById("riskBadge");
  const ruleScore = document.getElementById("ruleScore");
  const modelScore = document.getElementById("modelScore");
  const confidence = document.getElementById("confidence");
  const disclaimer = document.getElementById("disclaimer");
  const historyList = document.getElementById("historyList");
  const clearHistory = document.getElementById("clearHistory");

  const HISTORY_KEY = "phishguard_v3_history";

  const suspiciousWords = [
    "login","signin","verify","verification","account","secure","security",
    "update","password","confirm","bank","wallet","payment","invoice",
    "recover","unlock","bonus","free","gift","claim","alert"
  ];

  const shorteners = new Set([
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly",
    "cutt.ly","shorturl.at","rebrand.ly","tiny.cc"
  ]);

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, ch => ({
      "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
    }[ch]));
  }

  function isIP(host) {
    const parts = host.split(".");
    return parts.length === 4 &&
      parts.every(p => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
  }

  function entropy(text) {
    if (!text) return 0;
    const counts = {};
    for (const ch of text) counts[ch] = (counts[ch] || 0) + 1;
    let total = 0;
    for (const n of Object.values(counts)) {
      const p = n / text.length;
      total -= p * Math.log2(p);
    }
    return total;
  }

  function analyze(raw) {
    let value = raw.trim();
    if (!value) {
      return { valid:false, message:"Please enter a URL first." };
    }

    let normalized = value;
    if (!/^https?:\/\//i.test(normalized)) normalized = "https://" + normalized;

    let url;
    try {
      url = new URL(normalized);
    } catch {
      return { valid:false, message:"Please enter a valid URL, such as https://example.com" };
    }

    const host = url.hostname.toLowerCase();
    const text = normalized.toLowerCase();
    const findings = [];
    let rules = 0;

    if (url.protocol !== "https:") {
      rules += 18;
      findings.push("The URL does not use HTTPS.");
    }
    if (normalized.length > 100) {
      rules += 12;
      findings.push("The URL is unusually long.");
    }
    if (normalized.length > 180) {
      rules += 8;
      findings.push("The URL is extremely long.");
    }
    if (isIP(host)) {
      rules += 25;
      findings.push("The hostname is an IP address instead of a normal domain.");
    }
    if ((host.match(/-/g) || []).length >= 2) {
      rules += 10;
      findings.push("The hostname contains multiple hyphens.");
    }
    if (host.split(".").length >= 4) {
      rules += 8;
      findings.push("The hostname contains many subdomains.");
    }
    if (text.includes("@")) {
      rules += 20;
      findings.push("The URL contains an @ symbol, which can hide the real destination.");
    }
    if (shorteners.has(host)) {
      rules += 18;
      findings.push("The domain is a URL-shortening service.");
    }

    const hits = suspiciousWords.filter(word => text.includes(word));
    if (hits.length) {
      rules += Math.min(30, hits.length * 6);
      findings.push("Security-sensitive words detected: " + hits.slice(0, 5).join(", ") + ".");
    }

    if ((normalized.match(/%[0-9a-f]{2}/gi) || []).length >= 4) {
      rules += 8;
      findings.push("The URL contains heavy percent-encoding.");
    }

    if ((host.match(/\d/g) || []).length >= 5 && !isIP(host)) {
      rules += 8;
      findings.push("The hostname contains an unusual number of digits.");
    }

    rules = Math.min(100, rules);

    const lengthSignal = Math.min(1, Math.max(0, (normalized.length - 55) / 160));
    const entropySignal = Math.min(1, Math.max(0, (entropy(host) - 3.2) / 2.2));
    const digitSignal = Math.min(1, (host.match(/\d/g) || []).length / 8);

    const model = Math.round(100 * (
      0.35 * lengthSignal +
      0.30 * entropySignal +
      0.15 * digitSignal +
      0.20 * (hits.length ? 1 : 0)
    ));

    const score = Math.max(0, Math.min(100, Math.round(
      0.65 * rules + 0.35 * model
    )));

    if (!findings.length) {
      findings.push("No major phishing indicators were detected by the local checks.");
    }

    const verdict = score >= 70 ? "HIGH RISK" : score >= 40 ? "SUSPICIOUS" : "LOW RISK";
    const confidence = Math.min(99, Math.round(72 + Math.abs(score - 50) * 0.45));

    return {
      valid:true, url:normalized, host, score, verdict,
      findings, rules, model, confidence
    };
  }

  function saveHistory(item) {
    let history = [];
    try { history = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); } catch {}
    history = history.filter(x => x.url !== item.url);
    history.unshift(item);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 8)));
    renderHistory();
  }

  function renderHistory() {
    if (!historyList) return;
    let history = [];
    try { history = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); } catch {}

    if (!history.length) {
      historyList.innerHTML = '<div class="muted">No scans yet.</div>';
      return;
    }

    historyList.innerHTML = history.map(item => {
      const level = item.score >= 70 ? "high" : item.score >= 40 ? "medium" : "low";
      const icon = level === "high" ? "!" : level === "medium" ? "!" : "✓";
      const shortHost = item.host || item.url.replace(/^https?:\/\//i, "").split("/")[0];
      return `
        <button class="history-item" data-history-url="${escapeHtml(item.url)}" type="button">
          <span class="history-icon ${level}">${icon}</span>
          <span>
            <span class="history-url">${escapeHtml(shortHost)}</span>
            <span class="history-label">${escapeHtml(item.verdict || (level === "high" ? "HIGH RISK" : level === "medium" ? "SUSPICIOUS" : "LOW RISK"))}</span>
          </span>
          <span class="history-score">${item.score}/100</span>
        </button>`;
    }).join("");

    historyList.querySelectorAll("[data-history-url]").forEach(btn => {
      btn.addEventListener("click", () => {
        input.value = btn.getAttribute("data-history-url");
        scan();
      });
    });
  }

  function showResult(data) {
    result.classList.remove("hidden");
    result.style.display = "grid";

    label.textContent = data.verdict;
    domain.textContent = data.url;
    scoreEl.textContent = data.score;
    meterFill.style.width = data.score + "%";
    ruleScore.textContent = data.rules;
    modelScore.textContent = data.model;
    confidence.textContent = data.confidence + "%";

    findingsList.innerHTML = data.findings
      .map(item => `<p>• ${escapeHtml(item)}</p>`)
      .join("");

    riskBadge.textContent = data.verdict;

    if (data.score >= 70) {
      explanation.textContent =
        "Multiple signals indicate elevated phishing risk. Do not enter passwords, payment information, or other sensitive data on this destination.";
      disclaimer.textContent = "High-risk result. Treat this URL with caution.";
    } else if (data.score >= 40) {
      explanation.textContent =
        "Some characteristics deserve caution. Verify the domain independently before entering sensitive information.";
      disclaimer.textContent = "Suspicious result. Verify the destination before continuing.";
    } else {
      explanation.textContent =
        "The local checks found few phishing indicators. This does not guarantee that the website is safe.";
      disclaimer.textContent = "Low-risk result based on local URL analysis only.";
    }
  }

  function scan() {
    const data = analyze(input.value);

    if (!data.valid) {
      result.classList.remove("hidden");
      result.style.display = "grid";
      label.textContent = "INVALID URL";
      domain.textContent = data.message;
      scoreEl.textContent = "—";
      meterFill.style.width = "0%";
      findingsList.innerHTML = `<p>• ${escapeHtml(data.message)}</p>`;
      explanation.textContent = "Enter a complete URL and try again.";
      riskBadge.textContent = "INVALID";
      ruleScore.textContent = "0";
      modelScore.textContent = "0";
      confidence.textContent = "0%";
      disclaimer.textContent = "";
      return;
    }

    showResult(data);
    saveHistory(data);
  }

  scanBtn.addEventListener("click", scan);

  input.addEventListener("keydown", event => {
    if (event.key === "Enter") {
      event.preventDefault();
      scan();
    }
  });

  // The HTML uses data-url for these example buttons.
  document.querySelectorAll("[data-url]").forEach(button => {
    button.addEventListener("click", () => {
      input.value = button.getAttribute("data-url");
      scan();
    });
  });

  clearHistory.addEventListener("click", () => {
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
  });

  renderHistory();
});