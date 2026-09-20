const $ = id => document.getElementById(id);
const input = $("urlInput");
const scanBtn = $("scanBtn");
const result = $("result");
const historyKey = "phishguard_v3_history";

const suspiciousWords = [
  "login","signin","verify","verification","account","secure","security",
  "update","password","confirm","bank","wallet","payment","invoice",
  "recover","unlock","bonus","free","gift","claim","alert"
];
const shorteners = new Set([
  "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly",
  "cutt.ly","shorturl.at","rebrand.ly","tiny.cc"
]);

function isIP(host){
  const p = host.split(".");
  return p.length === 4 && p.every(x => /^\d+$/.test(x) && Number(x) >= 0 && Number(x) <= 255);
}
function entropy(s){
  if(!s) return 0;
  const c = {};
  for(const ch of s) c[ch] = (c[ch] || 0) + 1;
  let e = 0;
  for(const n of Object.values(c)){
    const p = n / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}
function analyze(raw){
  let url = raw.trim();
  if(!/^https?:\/\//i.test(url)) url = "https://" + url;
  let u;
  try { u = new URL(url); } catch(e) {
    return {valid:false, url:raw, score:100, verdict:"INVALID URL",
      reasons:["The entered value is not a valid URL."]};
  }

  const host = u.hostname.toLowerCase();
  const text = url.toLowerCase();
  const reasons = [];
  let score = 0;
  let ruleScore = 0;

  if(u.protocol !== "https:"){ ruleScore += 18; reasons.push("The URL does not use HTTPS."); }
  if(url.length > 100){ ruleScore += 12; reasons.push("The URL is unusually long."); }
  if(url.length > 180){ ruleScore += 8; reasons.push("The URL is extremely long."); }
  if(isIP(host)){ ruleScore += 25; reasons.push("The hostname is an IP address instead of a normal domain."); }
  if((host.match(/-/g)||[]).length >= 2){ ruleScore += 10; reasons.push("The hostname contains multiple hyphens."); }
  if(host.split(".").length >= 4){ ruleScore += 8; reasons.push("The hostname has many subdomains."); }
  if(text.includes("@")){ ruleScore += 20; reasons.push("The URL contains an @ symbol, which can hide the real destination."); }
  if(shorteners.has(host)){ ruleScore += 18; reasons.push("The domain is a URL-shortening service."); }

  const hits = suspiciousWords.filter(w => text.includes(w));
  if(hits.length){
    ruleScore += Math.min(30, hits.length * 6);
    reasons.push("Security-sensitive words detected: " + hits.slice(0,5).join(", ") + ".");
  }
  if((url.match(/%[0-9a-f]{2}/gi)||[]).length >= 4){
    ruleScore += 8; reasons.push("The URL contains heavy percent-encoding.");
  }
  if((host.match(/\d/g)||[]).length >= 5 && !isIP(host)){
    ruleScore += 8; reasons.push("The hostname contains an unusual number of digits.");
  }

  ruleScore = Math.min(100, ruleScore);

  // A lightweight local statistical-style component.
  const lengthSignal = Math.min(1, Math.max(0, (url.length - 55) / 160));
  const entropySignal = Math.min(1, Math.max(0, (entropy(host) - 3.2) / 2.2));
  const digitSignal = Math.min(1, (host.match(/\d/g)||[]).length / 8);
  const modelScore = Math.round(
    100 * (0.35*lengthSignal + 0.30*entropySignal + 0.15*digitSignal +
           0.20*(hits.length ? 1 : 0))
  );

  score = Math.round(0.65 * ruleScore + 0.35 * modelScore);
  score = Math.max(0, Math.min(100, score));

  if(!reasons.length) reasons.push("No major phishing indicators were detected by the local checks.");
  const verdict = score >= 70 ? "HIGH RISK" : score >= 40 ? "SUSPICIOUS" : "LOW RISK";
  const confidence = Math.round(Math.min(99, 72 + Math.abs(score-50)*0.45));

  return {valid:true,url,host,score,verdict,reasons,ruleScore,modelScore,confidence};
}

function history(){
  try { return JSON.parse(localStorage.getItem(historyKey) || "[]"); }
  catch(e){ return []; }
}
function save(item){
  const h = history().filter(x => x.url !== item.url);
  h.unshift(item);
  localStorage.setItem(historyKey, JSON.stringify(h.slice(0,8)));
}
function renderHistory(){
  const h = history();
  const box = document.querySelector("[data-history]");
  if(!box) return;
  if(!h.length){ box.innerHTML = '<div class="empty-history">No scans yet — your recent scans will appear here.</div>'; return; }
  box.innerHTML = h.map(x =>
    `<div class="history-item"><span>${escapeHtml(x.host || x.url)}</span><strong>${x.score}/100</strong></div>`
  ).join("");
}
function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}
function show(r){
  if(!result) return;
  result.style.display = "block";
  const colorClass = r.score >= 70 ? "danger" : r.score >= 40 ? "warning" : "safe";
  result.innerHTML = `
    <div class="result-card ${colorClass}">
      <div class="result-top">
        <div><span class="eyebrow">SECURITY ASSESSMENT</span><h2>${escapeHtml(r.verdict)}</h2></div>
        <div class="risk-score"><b>${r.score}</b><span>/100</span><small>RISK SCORE</small></div>
      </div>
      <p class="scanned-url">${escapeHtml(r.url)}</p>
      <div class="metrics">
        <div><b>${r.ruleScore}</b><span>Rule Engine</span></div>
        <div><b>${r.modelScore}</b><span>ML Model</span></div>
        <div><b>${r.confidence}%</b><span>Confidence</span></div>
      </div>
      <div class="analysis-details">
        <h3>Analysis Details</h3>
        <ul>${r.reasons.map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ul>
      </div>
      <div class="ai-explanation">
        <b>AI-Assisted Explanation</b>
        <p>${r.score >= 70
          ? "Multiple signals indicate elevated phishing risk. Do not enter passwords, payment information, or other sensitive data on this destination."
          : r.score >= 40
          ? "Some characteristics deserve caution. Verify the domain independently before entering sensitive information."
          : "The local checks found few phishing indicators. This does not guarantee that the website is safe."}</p>
      </div>
    </div>`;
}
function scan(raw){
  const r = analyze(raw);
  show(r);
  if(r.valid){ save(r); renderHistory(); }
}
scanBtn?.addEventListener("click", () => scan(input.value));
input?.addEventListener("keydown", e => { if(e.key === "Enter") scan(input.value); });
document.querySelectorAll("[data-example]").forEach(b =>
  b.addEventListener("click", () => { input.value = b.dataset.example; scan(input.value); })
);
renderHistory();
