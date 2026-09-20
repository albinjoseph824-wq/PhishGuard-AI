const $=id=>document.getElementById(id);
const input=$("urlInput"),btn=$("scanBtn"),result=$("result");
const HISTORY_KEY="phishguard_v3_history";

function renderHistory(){
  const list=$("historyList"), items=JSON.parse(localStorage.getItem(HISTORY_KEY)||"[]");
  if(!items.length){list.innerHTML='<p style="color:#6d8198;font-size:10px">No scans yet. Your recent results will appear here.</p>';return}
  list.innerHTML=items.slice(0,6).map(x=>`
    <div class="history-item">
      <div class="history-icon ${x.level}">${x.level==="low"?"✓":x.level==="high"?"!":"•"}</div>
      <div><div class="history-url" title="${x.url}">${x.url}</div><div class="history-label">${x.label}</div></div>
      <div class="history-score">${x.score}</div>
    </div>`).join("");
}
function saveHistory(d){
  const items=JSON.parse(localStorage.getItem(HISTORY_KEY)||"[]");
  items.unshift({url:d.url,label:d.label,score:d.score,level:d.level});
  localStorage.setItem(HISTORY_KEY,JSON.stringify(items.slice(0,12)));renderHistory();
}
async function scan(){
  const url=input.value.trim(); if(!url){input.focus();return}
  btn.disabled=true;btn.innerHTML="Analyzing <span>…</span>";
  try{
    const r=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url})});
    const d=await r.json(); result.classList.remove("hidden");
    if(d.status!=="ok"){$("label").textContent="Invalid URL";$("domain").textContent=d.message;return}
    $("label").textContent=d.label;$("domain").textContent=d.domain;$("score").textContent=d.score;
    $("ruleScore").textContent=d.rule_score;$("modelScore").textContent=d.model_score;$("confidence").textContent=d.confidence;
    $("meterFill").style.width=d.score+"%";$("explanation").textContent=d.explanation;
    $("riskBadge").textContent=d.level==="high"?"HIGH RISK":d.level==="medium"?"MEDIUM RISK":"LOW RISK";
    $("findingsList").innerHTML=d.findings.map(f=>`<div class="finding"><b style="color:${f.severity==="high"?"#ff5474":f.severity==="medium"?"#ffc451":"#35e7a2"}">${f.severity}</b>${f.text}</div>`).join("");
    $("disclaimer").textContent=d.disclaimer;saveHistory(d);
    result.scrollIntoView({behavior:"smooth",block:"center"});
  }catch(e){$("label").textContent="Server error";$("domain").textContent="Make sure Flask is running in the terminal."}
  finally{btn.disabled=false;btn.innerHTML="Scan URL <span>→</span>"}
}
btn.onclick=scan;input.onkeydown=e=>{if(e.key==="Enter")scan()};
document.querySelectorAll("[data-url]").forEach(x=>x.onclick=()=>{input.value=x.dataset.url;scan()});
$("clearHistory").onclick=()=>{localStorage.removeItem(HISTORY_KEY);renderHistory()};
renderHistory();
