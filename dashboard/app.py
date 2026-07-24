#!/usr/bin/env python3
"""
SEE-Monitor: Dashboard SPA
Single-page email-security dashboard. Exposes DASHBOARD_HTML, rendered by the
app blueprint via render_template_string with {{ version }}, {{ username }}
and {{ role }}. All data is fetched from /app/api/* (see app_routes.py).

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SEE-Monitor — Email Security Dashboard</title>
<style>
  :root{
    --bg:#0f1419; --panel:#1a2029; --panel2:#212936; --border:#2c3542;
    --text:#e4e9f0; --muted:#8a97a8; --accent:#4a90d9;
    --r-not:#d64545; --r-med:#e0a030; --r-strong:#4a90d9; --r-vstrong:#3aa76d;
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
       background:var(--bg);color:var(--text);font-size:14px}
  header{display:flex;align-items:center;gap:1rem;padding:.7rem 1.2rem;
         background:var(--panel);border-bottom:1px solid var(--border)}
  header .logo{font-weight:700;letter-spacing:.5px}
  header .logo em{color:var(--accent);font-style:normal}
  header .spacer{margin-left:auto}
  header .user{color:var(--muted);font-size:.8rem}
  header a{color:var(--muted);text-decoration:none;margin-left:1rem;font-size:.8rem}
  header a:hover{color:var(--text)}
  nav{display:flex;gap:.25rem;padding:.5rem 1.2rem;background:var(--panel2);
      border-bottom:1px solid var(--border);flex-wrap:wrap}
  nav button{background:none;border:1px solid transparent;color:var(--muted);
             padding:.4rem .8rem;border-radius:5px;cursor:pointer;font-size:.85rem}
  nav button:hover{color:var(--text)}
  nav button.active{background:var(--panel);color:var(--text);
                    border-color:var(--border)}
  main{padding:1.2rem;max-width:1200px;margin:0 auto}
  .grid{display:grid;gap:1rem}
  .cards{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
  .panel{background:var(--panel);border:1px solid var(--border);
         border-radius:8px;padding:1rem}
  .panel h3{margin:.1rem 0 .8rem;font-size:.8rem;text-transform:uppercase;
            letter-spacing:.5px;color:var(--muted)}
  .kpi{font-size:1.9rem;font-weight:700}
  .kpi small{font-size:.8rem;color:var(--muted);font-weight:400}
  table{width:100%;border-collapse:collapse}
  th,td{text-align:left;padding:.5rem .6rem;border-bottom:1px solid var(--border);
        font-size:.85rem}
  th{color:var(--muted);font-weight:600;cursor:pointer;user-select:none}
  tr.clickable{cursor:pointer}
  tr.clickable:hover td{background:var(--panel2)}
  .pill{display:inline-block;padding:.12rem .5rem;border-radius:20px;
        font-size:.72rem;font-weight:600;color:#0f1419}
  .r-not_implemented{background:var(--r-not);color:#fff}
  .r-medium{background:var(--r-med)}
  .r-strong{background:var(--r-strong);color:#fff}
  .r-very_strong{background:var(--r-vstrong);color:#fff}
  .r-partial{background:var(--r-med)}
  .r-compliant{background:var(--r-vstrong);color:#fff}
  .bar{height:8px;border-radius:4px;background:var(--panel2);overflow:hidden}
  .bar>span{display:block;height:100%}
  .ctrlrow{display:flex;align-items:center;gap:.6rem;margin:.3rem 0}
  .ctrlrow .lbl{width:90px;font-size:.8rem;color:var(--muted)}
  .ctrlrow .bar{flex:1}
  .ctrlrow .val{width:44px;text-align:right;font-size:.8rem}
  .muted{color:var(--muted)}
  .btn{background:var(--accent);border:none;color:#fff;padding:.4rem .8rem;
       border-radius:5px;cursor:pointer;font-size:.82rem}
  .btn.ghost{background:none;border:1px solid var(--border);color:var(--text)}
  .btn:hover{opacity:.9}
  input,select{background:var(--panel2);border:1px solid var(--border);
               color:var(--text);padding:.4rem .5rem;border-radius:5px}
  .sev-critical{color:var(--r-not)}
  .sev-warning{color:var(--r-med)}
  .sev-info{color:var(--muted)}
  .back{cursor:pointer;color:var(--accent);font-size:.82rem;margin-bottom:.6rem;
        display:inline-block}
  code{background:var(--panel2);padding:.1rem .3rem;border-radius:3px;
       font-size:.78rem;word-break:break-all}
  .tag{font-size:.68rem;color:var(--muted);border:1px solid var(--border);
       border-radius:3px;padding:.05rem .3rem;margin-left:.3rem}
  .phase{border-left:3px solid var(--accent);padding-left:.8rem;margin:.8rem 0}
  .phase h4{margin:.2rem 0}
  ul.acts{margin:.3rem 0;padding-left:1.1rem}
  ul.acts li{margin:.15rem 0}
  .empty{color:var(--muted);text-align:center;padding:2rem}
  .flex{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
  /* status dashboards */
  .statusbar{display:flex;height:26px;border-radius:6px;overflow:hidden;
             background:var(--panel2);border:1px solid var(--border)}
  .statusbar .seg{height:100%;cursor:pointer;transition:opacity .15s}
  .statusbar .seg:hover{opacity:.8}
  .statusbar.mini{height:12px;border-radius:3px}
  .legend{display:flex;flex-wrap:wrap;gap:.8rem;margin-top:.6rem;font-size:.78rem}
  .legend .legitem{display:flex;align-items:center;gap:.35rem;cursor:pointer}
  .legend i{width:11px;height:11px;border-radius:2px;display:inline-block}
  .legend b{font-weight:700}
  .statuskpi{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.4rem}
  .statuskpi .sk{flex:1;min-width:96px;background:var(--panel2);
    border:1px solid var(--border);border-radius:6px;padding:.5rem .6rem}
  .statuskpi .sk .n{font-size:1.5rem;font-weight:700;line-height:1}
  .statuskpi .sk .l{font-size:.66rem;text-transform:uppercase;
    letter-spacing:.4px;color:var(--muted);margin-top:.2rem}
  .gsel{display:flex;align-items:center;gap:.4rem;margin-left:auto}
  .gsel select{font-size:.82rem}
  .trendwrap{overflow-x:auto}
  svg.trend{width:100%;min-width:520px;height:auto;display:block}
  svg.trend text{fill:var(--muted);font-size:10px}
  svg.trend .axis{stroke:var(--border);stroke-width:1}
  svg.trend .grid{stroke:var(--border);stroke-dasharray:2 3;opacity:.5}
  svg.trend .scoreline{fill:none;stroke:var(--accent);stroke-width:2}
  svg.trend .scoredot{fill:var(--accent)}
  .periodsel{display:flex;gap:.25rem}
  .periodsel button{background:none;border:1px solid var(--border);
    color:var(--muted);padding:.25rem .6rem;border-radius:5px;cursor:pointer;
    font-size:.78rem}
  .periodsel button.active{background:var(--accent);color:#fff;
    border-color:var(--accent)}
</style>
</head>
<body>
<header>
  <span class="logo">SEE<em>-</em>Monitor</span>
  <span class="tag">v{{ version }}</span>
  <span class="spacer"></span>
  <span class="user">{{ username }} · {{ role }}</span>
  {% if role == 'admin' %}<a href="/admin/">Admin</a>{% endif %}
  <a href="/logout">Sign out</a>
</header>
<nav id="nav">
  <button data-view="overview" class="active">Overview</button>
  <button data-view="domains">Domains</button>
  <button data-view="organisations">Organisations</button>
  <button data-view="groups">Group reports</button>
  <button data-view="trends">Trends</button>
  <button data-view="roadmap">Roadmap</button>
  <button data-view="runs">Scans</button>
  <span class="gsel">Standard:
    <select id="gsel" onchange="setGuideline(this.value)"></select></span>
</nav>
<main id="main"><div class="empty">Loading…</div></main>

<script>
const ROLE = "{{ role }}";
const CONTROLS = ["spf","dkim","dmarc","starttls","dnssec","dane",
                  "mta_sts","tlsrpt","bimi"];
const CTRL_LABEL = {spf:"SPF",dkim:"DKIM",dmarc:"DMARC",starttls:"STARTTLS",
  dnssec:"DNSSEC",dane:"DANE",mta_sts:"MTA-STS",tlsrpt:"TLS-RPT",bimi:"BIMI"};
const RATING_LABEL = {not_implemented:"Not impl./Weak",medium:"Medium",
  strong:"Strong",very_strong:"Very strong",partial:"Partial",
  compliant:"Compliant"};
const RATING_COLOR = {not_implemented:"#d64545",medium:"#e0a030",
  strong:"#4a90d9",very_strong:"#3aa76d",partial:"#e0a030",compliant:"#3aa76d"};
const $ = s => document.querySelector(s);
const esc = s => String(s==null?"":s).replace(/[&<>"]/g,
  c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

// ---- Conformance profile (guideline) state --------------------------
let GUIDELINE = "nist_800_177r1";
let GUIDELINES = [];                       // [{id,name,bands,...}]
function currentGuideline(){ return GUIDELINES.find(g=>g.id===GUIDELINE); }
function guidelineBands(){                  // ascending by min_score
  const g = currentGuideline();
  if(g && g.bands && g.bands.length) return g.bands;
  return [{rating:"not_implemented"},{rating:"medium"},
          {rating:"strong"},{rating:"very_strong"}];
}
// best rating first (for legends / stacked order)
function ratingOrder(){ return guidelineBands().map(b=>b.rating).reverse(); }
function ratingLabel(r){
  const b = guidelineBands().find(x=>x.rating===r);
  return (b&&b.label) || RATING_LABEL[r] || r;
}
function ratingColor(r){
  const b = guidelineBands().find(x=>x.rating===r);
  return (b&&b.color) || RATING_COLOR[r] || "var(--muted)";
}
async function setGuideline(id){ GUIDELINE = id; render(); }

async function api(path, opts){
  // Auto-scope GET requests to the selected conformance profile.
  if(!opts){
    path += (path.includes("?")?"&":"?") + "guideline=" +
            encodeURIComponent(GUIDELINE);
  }
  const r = await fetch("/app/api"+path, opts);
  if(!r.ok) throw new Error((await r.json().catch(()=>({}))).error||r.status);
  return r.json();
}
function scoreColor(v){
  if(v==null) return "var(--muted)";
  if(v>=85) return "var(--r-vstrong)";
  if(v>=60) return "var(--r-strong)";
  if(v>=30) return "var(--r-med)";
  return "var(--r-not)";
}
function ratingPill(r){
  return `<span class="pill" style="background:${ratingColor(r)};color:#fff">${
    esc(ratingLabel(r))}</span>`;
}
// Segmented status-distribution bar. `link` => clicking a segment/legend
// opens the domains list filtered to that rating.
function statusBar(ratings, opts){
  opts = opts||{};
  const order = ratingOrder();
  const total = order.reduce((s,r)=>s+(ratings[r]||0),0);
  if(!total) return '<div class="muted">No assessments in scope.</div>';
  const mini = opts.mini?" mini":"";
  const clk = r => opts.link?` onclick="go('domains','${r}')"`:"";
  const segs = order.map(r=>{
    const n = ratings[r]||0; if(!n) return "";
    return `<span class="seg" title="${esc(ratingLabel(r))}: ${n}"
      style="width:${100*n/total}%;background:${ratingColor(r)}"${clk(r)}></span>`;
  }).join("");
  const legend = order.filter(r=>ratings[r]).map(r=>
    `<span class="legitem"${clk(r)}><i style="background:${ratingColor(r)}"></i>${
      esc(ratingLabel(r))} <b>${ratings[r]}</b> <span class="muted">(${
      Math.round(100*ratings[r]/total)}%)</span></span>`).join("");
  return `<div class="statusbar${mini}">${segs}</div>`+
         (opts.mini?"":`<div class="legend">${legend}</div>`);
}
function statusKpis(ratings, total){
  const order = ratingOrder();
  const cards = order.map(r=>`<div class="sk"><div class="n"
    style="color:${ratingColor(r)}">${ratings[r]||0}</div>
    <div class="l">${esc(ratingLabel(r))}</div></div>`).join("");
  return `<div class="statuskpi">${cards}</div>`;
}
function ctrlBar(label,v){
  const val = v==null?"n/a":Math.round(v);
  const w = v==null?0:v;
  return `<div class="ctrlrow"><span class="lbl">${label}</span>
    <span class="bar"><span style="width:${w}%;background:${scoreColor(v)}"></span></span>
    <span class="val">${val}</span></div>`;
}

// ---- Views ----------------------------------------------------------
const views = {};

views.overview = async () => {
  const s = await api("/summary");
  const rd = s.ratings||{};
  const total = s.total_domains||0;
  const g = currentGuideline();
  const top = ratingOrder()[0];                 // best rating for this profile
  const good = rd[top]||0;
  const pctGood = total? Math.round(100*good/total):0;

  const kpis = `
    <div class="panel"><h3>Domains assessed</h3><div class="kpi">${total}</div></div>
    <div class="panel"><h3>Average score</h3>
      <div class="kpi" style="color:${scoreColor(s.avg_score)}">${s.avg_score??0}
      <small>/100</small></div></div>
    <div class="panel"><h3>${esc(ratingLabel(top))}</h3>
      <div class="kpi" style="color:${ratingColor(top)}">${good}
      <small>/ ${total} (${pctGood}%)</small></div></div>`;

  let ctrls = "";
  for(const c of CONTROLS){
    const ci = (s.controls||{})[c]||{implemented:0,applicable:0};
    const pct = ci.applicable? Math.round(100*ci.implemented/ci.applicable):null;
    ctrls += `<div class="ctrlrow"><span class="lbl">${CTRL_LABEL[c]}</span>
      <span class="bar"><span style="width:${pct||0}%;background:var(--accent)"></span></span>
      <span class="val">${pct==null?"—":pct+"%"}</span></div>
      <div class="muted" style="font-size:.7rem;margin:-.15rem 0 .3rem 90px">
        ${ci.implemented}/${ci.applicable} domains</div>`;
  }

  return `<div class="grid cards">${kpis}</div>
    <div class="panel" style="margin-top:1rem">
      <h3>Status distribution — ${esc(g?g.name:GUIDELINE)}</h3>
      ${total? statusBar(rd,{link:true})+statusKpis(rd,total)
             : '<div class="empty">No assessments yet</div>'}
      <div class="muted" style="font-size:.72rem;margin-top:.6rem">
        Click a status to list those domains.</div>
    </div>
    <div class="panel" style="margin-top:1rem"><h3>Control implementation rate</h3>
      ${total?ctrls:'<div class="empty">No assessments yet</div>'}</div>`;
};

let _domainCache = [];
views.domains = async (filterRating) => {
  const list = await api("/assessments");
  _domainCache = list;
  if(!list.length) return `<div class="panel"><div class="empty">
    No assessed domains yet. Scan some from the Scans tab.</div></div>`;
  let shown = list.slice().sort((a,b)=>a.score-b.score);
  if(filterRating) shown = shown.filter(a=>a.rating===filterRating);
  const chips = ["",...ratingOrder()].map(r=>{
    const active = (r||"")===(filterRating||"");
    const lbl = r? ratingLabel(r) : "All";
    const bg = active? (r?ratingColor(r):"var(--accent)") : "transparent";
    const col = active? "#fff" : "var(--muted)";
    return `<button class="btn ghost" style="background:${bg};color:${col};
      border-color:${r?ratingColor(r):'var(--border)'}"
      onclick="go('domains'${r?`,'${r}'`:''})">${esc(lbl)}</button>`;
  }).join("");
  let rows = shown.map(a=>`
    <tr class="clickable" onclick="go('domain','${esc(a.domain)}')">
      <td>${esc(a.domain)}</td>
      <td><span style="color:${scoreColor(a.score)};font-weight:600">${a.score}</span></td>
      <td>${ratingPill(a.rating)}</td>
      <td class="muted">${a.no_mail?'<span class="tag">no mail</span>':''}</td>
    </tr>`).join("");
  return `<div class="panel"><h3>Assessed domains — ${esc(GUIDELINE)}
      (${shown.length}${filterRating?` of ${list.length}`:''})</h3>
    <div class="flex" style="margin-bottom:.6rem">${chips}</div>
    <table><thead><tr><th>Domain</th><th>Score</th><th>Rating</th><th></th></tr>
    </thead><tbody>${rows||'<tr><td class="muted">None with this status.</td></tr>'}
    </tbody></table></div>`;
};

views.domain = async (domain) => {
  const d = await api("/domain/"+encodeURIComponent(domain));
  const a = d.latest;
  const checks = d.checks||{};
  let head = `<span class="back" onclick="go('domains')">← Domains</span>
    <div class="panel"><div class="flex">
      <h3 style="margin:0">${esc(domain)}</h3>
      ${a?ratingPill(a.rating):''}
      ${a?`<span style="color:${scoreColor(a.score)};font-weight:700;font-size:1.2rem">${a.score}</span>`:''}
      <span class="spacer" style="margin-left:auto"></span>
      <button class="btn ghost" onclick="rescan('${esc(domain)}')">Re-scan</button>
      <button class="btn ghost" onclick="go('trends','domain=${encodeURIComponent(domain)}','domain: ${esc(domain)}')">Trends</button>
      <button class="btn" onclick="go('roadmap','${esc(domain)}')">Roadmap</button>
    </div>`;
  if(!a){ return head + `<div class="empty">No assessment yet.</div></div>`; }

  let bars = CONTROLS.map(c=>ctrlBar(CTRL_LABEL[c], a.control_scores[c])).join("");
  let findings = (a.findings||[]).map(f=>`<li class="sev-${f.severity}">
    <b>${CTRL_LABEL[f.control]||f.control}:</b> ${esc(f.message)}</li>`).join("")
    || '<li class="muted">No issues.</li>';

  // technical drill-down
  let tech = "";
  const mx = checks.mx;
  if(mx){
    tech += `<div class="panel"><h3>MX</h3>`;
    if(mx.null_mx) tech += `<div>Null MX (RFC 7505) — domain refuses mail.</div>`;
    else if(!mx.has_mx) tech += `<div class="muted">No MX records.</div>`;
    else tech += mx.mx_hosts.map(m=>`<div><code>${esc(m.host)}</code>
      <span class="muted">pri ${m.priority}</span></div>`).join("");
    if((mx.invalid_records||[]).length) tech +=
      `<div class="sev-warning">Ignored malformed: ${mx.invalid_records.map(esc).join(", ")}</div>`;
    tech += `</div>`;
  }
  tech += techPanel("SPF", checks.spf, s=>s.record?`<code>${esc(s.record)}</code>
     <div class="muted">all: ${esc(s.all_qualifier||'—')} · lookups: ${s.lookup_count}</div>`:'');
  tech += techPanel("DMARC", checks.dmarc, s=>s.record?`<code>${esc(s.record)}</code>
     <div class="muted">policy: ${esc(s.policy||'—')} · pct: ${s.pct} · rua: ${(s.rua||[]).length}</div>`:'');
  tech += dkimPanel(domain, checks.dkim, d.dkim_selectors||[]);
  tech += techPanel("STARTTLS", checks.starttls, s=>{
    if(!s.applicable) return '<div class="muted">Not applicable.</div>';
    return Object.entries(s.hosts||{}).map(([h,v])=>`<div><code>${esc(h)}</code>
      ${v.starttls_ok?'✓':'✗'} ${esc(v.tls_version||'')}
      <span class="muted">(${esc(v.source)})</span></div>`).join("")
      + `<div class="muted">coverage ${Math.round((s.coverage||0)*100)}%</div>`;
  });
  tech += techPanel("DNSSEC", checks.dnssec, s=>`<div>signed: ${s.signed} ·
     validated: ${s.validated===null?'?':s.validated}</div>`);
  tech += techPanel("DANE", checks.dane, s=>!s.applicable?'<div class="muted">Not applicable.</div>':
     `<div>TLSA on ${(s.mx_with_tlsa||[]).length}/${(s.mx_with_tlsa||[]).length+(s.mx_without_tlsa||[]).length} MX · usable: ${s.usable}</div>`);
  tech += techPanel("MTA-STS", checks.mta_sts, s=>s.present?
     `<div>mode: ${esc(s.mode||'—')} · fetched: ${s.policy_fetched}</div>`:'');
  tech += techPanel("TLS-RPT", checks.tlsrpt, s=>s.present?
     `<div>rua: ${(s.rua||[]).map(esc).join(", ")}</div>`:'');
  tech += techPanel("BIMI", checks.bimi, s=>s.present?
     `<div>VMC: ${s.vmc_url?'yes':'no'}</div>`:'');

  return head + `
    <div style="margin-top:.8rem">${bars}</div>
    </div>
    <div class="panel" style="margin-top:1rem"><h3>Findings</h3>
      <ul>${findings}</ul></div>
    <div class="grid cards" style="margin-top:1rem">${tech}</div>`;
};

function techPanel(title, data, render){
  if(!data) return "";
  let body;
  try{ body = render(data); }catch(e){ body=""; }
  if(!body) body = `<div class="muted">Not present.</div>`;
  return `<div class="panel"><h3>${title}</h3>${body}</div>`;
}

function dkimPanel(domain, data, registered){
  let body = "";
  if(data && (data.selectors||[]).length){
    body += (data.selectors).map(s=>`<div><code>${esc(s.selector)}</code>
      <span class="pill r-${s.status==='strong'?'very_strong':s.status==='weak'?'medium':'not_implemented'}">${esc(s.status)}</span>
      <span class="muted">${esc(s.key_type)} ${s.key_bits||''} · ${esc(s.source)}</span></div>`).join("");
  } else {
    body += `<div class="muted">No selectors discovered.</div>`;
  }
  body += `<div class="flex" style="margin-top:.5rem">
    <input id="sel-in" placeholder="register selector" style="flex:1">
    <button class="btn ghost" onclick="addSel('${esc(domain)}')">Add</button></div>`;
  if((registered||[]).length) body += `<div class="muted" style="margin-top:.4rem">
    Registered: ${registered.map(esc).join(", ")}</div>`;
  return `<div class="panel"><h3>DKIM</h3>${body}</div>`;
}

window.addSel = async (domain)=>{
  const v = $("#sel-in").value.trim(); if(!v) return;
  await api("/domain/"+encodeURIComponent(domain)+"/selectors",
    {method:"POST",headers:{"Content-Type":"application/json"},
     body:JSON.stringify({selector:v})});
  go('domain',domain);
};
window.rescan = async (domain)=>{
  await api("/scan",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({domains:[domain]})});
  alert("Scan queued for "+domain+". Refresh in a moment.");
};

views.organisations = async () => {
  const orgs = await api("/organisations");
  if(!orgs.length) return `<div class="panel"><div class="empty">
    No organisations visible.</div></div>`;
  let rows = orgs.map(o=>`
    <tr class="clickable" onclick="go('org',${o.id})">
      <td>${esc(o.name)}</td>
      <td>${o.domains}</td>
      <td style="color:${scoreColor(o.avg_score)}">${o.avg_score??'—'}</td>
      <td class="muted">${esc(o.country_code||'')} ${esc(o.region||'')}</td>
    </tr>`).join("");
  return `<div class="panel"><h3>Organisations (${orgs.length})</h3>
    <table><thead><tr><th>Name</th><th>Domains</th><th>Avg score</th>
    <th>Country/Region</th></tr></thead><tbody>${rows}</tbody></table></div>`;
};

views.org = async (id) => {
  const d = await api("/org/"+id);
  const o = d.organisation;
  let rows = (d.assessments||[]).sort((a,b)=>a.score-b.score).map(a=>`
    <tr class="clickable" onclick="go('domain','${esc(a.domain)}')">
      <td>${esc(a.domain)}</td>
      <td style="color:${scoreColor(a.score)}">${a.score}</td>
      <td>${ratingPill(a.rating)}</td></tr>`).join("");
  let unassessed = (d.unassessed||[]).map(x=>`<code>${esc(x)}</code>`).join(" ");
  return `<span class="back" onclick="go('organisations')">← Organisations</span>
    <div class="panel"><div class="flex"><h3 style="margin:0">${esc(o.name)}</h3>
      <span class="spacer" style="margin-left:auto"></span>
      <button class="btn ghost" onclick="groupRoadmap('org',${id})">Group roadmap</button>
    </div>
    <div class="muted">${esc(o.sector||'')} · ${esc(o.country_code||'')} ${esc(o.region||'')}</div>
    </div>
    <div class="panel" style="margin-top:1rem"><h3>Domains (${(d.assessments||[]).length})</h3>
    <table><tbody>${rows||'<tr><td class="muted">No assessments.</td></tr>'}</tbody></table>
    ${unassessed?`<div class="muted" style="margin-top:.6rem">Not yet assessed: ${unassessed}</div>`:''}
    </div>`;
};

views.groups = async () => {
  const [comms, countries, regions] = await Promise.all([
    api("/communities").catch(()=>[]),
    api("/countries").catch(()=>[]),
    api("/regions").catch(()=>[]),
  ]);
  const block = (title,items,fn)=>`<div class="panel"><h3>${title}</h3>${
    items.length? items.map(fn).join(""):'<div class="muted">None.</div>'}</div>`;
  return `<div class="grid cards">
    ${block("By community",comms,c=>`<div class="clickable" style="padding:.3rem 0"
       onclick="go('groupreport','community','${c.id}','${esc(c.name)}')">
       ${esc(c.name)} <span class="muted">(${c.org_count} orgs)</span></div>`)}
    ${block("By country",countries,c=>`<div class="clickable" style="padding:.3rem 0"
       onclick="go('groupreport','country','${esc(c.country_code)}','${esc(c.country_code)}')">
       ${esc(c.country_code)} <span class="muted">(${c.org_count} orgs)</span></div>`)}
    ${block("By region",regions,r=>`<div class="clickable" style="padding:.3rem 0"
       onclick="go('groupreport','region','${esc(r.region)}','${esc(r.region)}')">
       ${esc(r.region)} <span class="muted">(${r.org_count} orgs)</span></div>`)}
  </div>`;
};

views.groupreport = async (kind, key, label) => {
  const path = kind==="community" ? "/community/"+key+"/report"
             : kind==="country" ? "/country/"+encodeURIComponent(key)+"/report"
             : "/region/"+encodeURIComponent(key)+"/report";
  const d = await api(path);
  const t = d.totals||{};
  const rd = t.ratings||{};
  const g = currentGuideline();
  const rows = (d.organisations||[]).slice()
    .sort((a,b)=>(a.avg_score??999)-(b.avg_score??999))
    .map(o=>`<tr class="clickable" onclick="go('org',${o.id})">
      <td>${esc(o.name)}</td><td>${o.domains}</td>
      <td style="color:${scoreColor(o.avg_score)}">${o.avg_score??'—'}</td>
      <td style="min-width:120px">${
        Object.keys(o.ratings||{}).length? statusBar(o.ratings,{mini:true})
        :'<span class="muted">—</span>'}</td></tr>`).join("");
  const scopeQ = kind==="community"?`community=${encodeURIComponent(key)}`
               : kind==="country"?`country=${encodeURIComponent(key)}`
               : `region=${encodeURIComponent(key)}`;
  return `<span class="back" onclick="go('groups')">← Group reports</span>
    <div class="panel"><div class="flex" style="justify-content:space-between">
        <h3 style="margin:0">${esc(label)} — ${kind} · ${esc(g?g.name:GUIDELINE)}</h3>
        <button class="btn ghost" onclick="go('trends','${scopeQ}','${esc(label)}')">
          View trends →</button></div>
      <div class="flex" style="margin:.6rem 0"><b>${t.orgs||0}</b> orgs ·
        <b>${t.domains||0}</b> domains · avg
        <span style="color:${scoreColor(t.avg_score)}">${t.avg_score||0}</span></div>
      ${t.domains? statusBar(rd,{link:false}) :'<div class="muted">No assessments.</div>'}
    </div>
    <div class="panel" style="margin-top:1rem"><h3>Organisations</h3>
      <table><thead><tr><th>Name</th><th>Domains</th><th>Avg</th>
        <th>Status distribution</th></tr></thead>
      <tbody>${rows||'<tr><td class="muted">None.</td></tr>'}</tbody></table>
      <button class="btn ghost" style="margin-top:.8rem"
        onclick="groupRoadmap('${kind}','${esc(key)}')">Group roadmap</button></div>`;
};

// ---- Trends (timeline) ----------------------------------------------
let _trend = {scope:"", label:"all domains", period:"weekly"};
let _scopeOpts = null;                       // cached [{value,label}]

async function loadScopeOptions(){
  if(_scopeOpts) return _scopeOpts;
  const [comms,countries,regions] = await Promise.all([
    api("/communities").catch(()=>[]),
    api("/countries").catch(()=>[]),
    api("/regions").catch(()=>[]),
  ]);
  const o = [{value:"",label:"All domains"}];
  comms.forEach(c=>o.push({value:`community=${c.id}`,label:`Community: ${c.name}`}));
  countries.forEach(c=>o.push({value:`country=${encodeURIComponent(c.country_code)}`,
    label:`Country: ${c.country_code}`}));
  regions.forEach(r=>o.push({value:`region=${encodeURIComponent(r.region)}`,
    label:`Region: ${r.region}`}));
  _scopeOpts = o; return o;
}

function drawTrend(buckets){
  if(!buckets.length) return '<div class="empty">No assessment history in this scope yet.</div>';
  const W=800,H=300,padL=44,padR=44,padT=14,padB=56;
  const plotW=W-padL-padR, plotH=H-padT-padB, yB=padT+plotH;
  const n=buckets.length, bandW=plotW/n, barW=Math.min(bandW*0.62,46);
  const order=ratingOrder().slice().reverse();      // worst first (bottom)
  let maxTotal=1;
  buckets.forEach(b=>{const t=Object.values(b.ratings||{}).reduce((s,v)=>s+v,0);
    if(t>maxTotal)maxTotal=t;});
  const cx=i=>padL+bandW*(i+0.5);
  const yCount=v=>yB-(v/maxTotal)*plotH;
  const yScore=v=>yB-(v/100)*plotH;

  // gridlines + left (count) axis
  let g="";
  const cTicks=4;
  for(let i=0;i<=cTicks;i++){
    const v=Math.round(maxTotal*i/cTicks), y=yCount(v);
    g+=`<line class="grid" x1="${padL}" y1="${y}" x2="${padL+plotW}" y2="${y}"/>
        <text x="${padL-6}" y="${y+3}" text-anchor="end">${v}</text>`;
  }
  // right (score) axis
  [0,50,100].forEach(v=>{const y=yScore(v);
    g+=`<text x="${padL+plotW+6}" y="${y+3}" text-anchor="start"
         fill="var(--accent)">${v}</text>`;});

  // stacked bars
  let bars="";
  buckets.forEach((b,i)=>{
    let acc=0;
    order.forEach(r=>{
      const v=(b.ratings||{})[r]||0; if(!v) return;
      const h=(v/maxTotal)*plotH, y=yCount(acc+v);
      bars+=`<rect x="${cx(i)-barW/2}" y="${y}" width="${barW}" height="${h}"
        fill="${ratingColor(r)}"><title>${esc(b.label)} — ${esc(ratingLabel(r))}: ${v}</title></rect>`;
      acc+=v;
    });
  });
  // score line + dots
  const pts=buckets.map((b,i)=>`${cx(i)},${yScore(b.avg_score)}`).join(" ");
  let dots=buckets.map((b,i)=>`<circle class="scoredot" cx="${cx(i)}"
    cy="${yScore(b.avg_score)}" r="3"><title>${esc(b.label)} — avg ${b.avg_score}</title></circle>`).join("");
  // x labels (thin out if crowded)
  const step=Math.ceil(n/12);
  let xl=buckets.map((b,i)=> i%step? "" :
    `<text x="${cx(i)}" y="${yB+16}" text-anchor="middle">${esc(b.label)}</text>`).join("");

  return `<div class="trendwrap"><svg class="trend" viewBox="0 0 ${W} ${H}"
      preserveAspectRatio="xMidYMid meet">
    ${g}
    <line class="axis" x1="${padL}" y1="${yB}" x2="${padL+plotW}" y2="${yB}"/>
    ${bars}
    <polyline class="scoreline" points="${pts}"/>
    ${dots}${xl}
    <text x="${padL}" y="${H-6}" fill="var(--muted)">Bars: domain count per status · Line: avg score (0–100)</text>
  </svg></div>`;
}

views.trends = async (scopeQ, label) => {
  if(scopeQ!==undefined){ _trend.scope=scopeQ||""; _trend.label=label||"all domains"; }
  const opts = await loadScopeOptions();
  // Keep custom (e.g. single-domain) scopes selectable even if not in list.
  const inList = opts.some(o=>o.value===_trend.scope);
  const scopeSel = `<select id="tscope" onchange="trendScope(this.value)">
    ${opts.map(o=>`<option value="${esc(o.value)}"${o.value===_trend.scope?' selected':''}>${esc(o.label)}</option>`).join("")}
    ${inList?"":`<option value="${esc(_trend.scope)}" selected>${esc(_trend.label)}</option>`}
  </select>`;
  const periods=[["weekly","Weekly"],["monthly","Monthly"],
                 ["quarterly","Quarterly"],["yearly","Yearly"]];
  const pbtns=periods.map(([p,l])=>`<button class="${p===_trend.period?'active':''}"
    onclick="trendPeriod('${p}')">${l}</button>`).join("");

  let data;
  try{
    data = await api("/timeline?"+(_trend.scope?_trend.scope+"&":"")+"period="+_trend.period);
  }catch(e){
    return `<div class="panel"><div class="empty">Error: ${esc(e.message)}</div></div>`;
  }
  const b=data.buckets||[];
  const g=currentGuideline();
  // summary row
  const first=b[0], last=b[b.length-1];
  const delta=(first&&last)? Math.round((last.avg_score-first.avg_score)*10)/10 : 0;
  const deltaTxt=b.length>1? `<span style="color:${delta>=0?'var(--r-vstrong)':'var(--r-not)'}">
     ${delta>=0?'▲ +':'▼ '}${delta}</span> since ${esc(first.label)}`:'';
  const legend = ratingOrder().map(r=>
    `<span class="legitem"><i style="background:${ratingColor(r)}"></i>${esc(ratingLabel(r))}</span>`).join("")
    + `<span class="legitem"><i style="background:var(--accent)"></i>Avg score</span>`;

  let table = b.slice().reverse().map(x=>{
    const dist=ratingOrder().map(r=>(x.ratings||{})[r]?`${ratingLabel(r)} ${x.ratings[r]}`:"")
      .filter(Boolean).join(" · ");
    return `<tr><td>${esc(x.label)}</td>
      <td style="color:${scoreColor(x.avg_score)}">${x.avg_score}</td>
      <td>${x.domains}</td><td>${x.scans}</td>
      <td class="muted">${esc(dist)}</td></tr>`;}).join("");

  return `<div class="panel">
      <div class="flex" style="justify-content:space-between">
        <h3 style="margin:0">Trends — ${esc(g?g.name:GUIDELINE)}</h3>
        <div class="periodsel">${pbtns}</div>
      </div>
      <div class="flex" style="margin:.6rem 0">Scope: ${scopeSel}
        <span class="muted">or domain:</span>
        <input id="tdom" placeholder="example.com" style="width:180px"
          onkeydown="if(event.key==='Enter')trendDomain(this.value)">
        <button class="btn ghost" onclick="trendDomain($('#tdom').value)">Go</button>
        <span class="muted">${data.domains==null?'all':data.domains} domain(s) · ${deltaTxt}</span>
      </div>
      ${drawTrend(b)}
      <div class="legend" style="margin-top:.4rem">${legend}</div>
    </div>
    <div class="panel" style="margin-top:1rem"><h3>Per-period detail</h3>
      <table><thead><tr><th>Period</th><th>Avg score</th><th>Domains</th>
        <th>Scans</th><th>Status mix</th></tr></thead>
      <tbody>${table||'<tr><td class="muted">No data.</td></tr>'}</tbody></table></div>`;
};
window.trendPeriod = p => { _trend.period=p; render(); };
window.trendScope = v => {
  const o=(_scopeOpts||[]).find(x=>x.value===v);
  _trend.scope=v; _trend.label=o?o.label:v; render();
};
window.trendDomain = d => {
  d=(d||"").trim().toLowerCase();
  if(!d) return;
  _trend.scope="domain="+encodeURIComponent(d); _trend.label="domain: "+d; render();
};

let _roadmapDomain = null;
views.roadmap = async (domain) => {
  if(domain) _roadmapDomain = domain;
  if(!_roadmapDomain){
    if(!_domainCache.length){ try{_domainCache=await api("/assessments");}catch(e){} }
    let opts = _domainCache.map(a=>`<option>${esc(a.domain)}</option>`).join("");
    return `<div class="panel"><h3>Domain roadmap</h3>
      <div class="flex"><select id="rm-sel">${opts}</select>
      <button class="btn" onclick="_roadmapDomain=$('#rm-sel').value;render()">Show</button>
      </div>${!_domainCache.length?'<div class="empty">No assessed domains.</div>':''}</div>`;
  }
  let d;
  try{ d = await api("/roadmap/domain/"+encodeURIComponent(_roadmapDomain)); }
  catch(e){ return `<span class="back" onclick="_roadmapDomain=null;render()">← Back</span>
    <div class="panel"><div class="empty">${esc(e.message)}</div></div>`; }
  let phases = (d.phases||[]).map(p=>`<div class="phase"><h4>${esc(p.label)}</h4>
    ${p.activities.map(a=>`<div style="margin:.4rem 0"><b>${esc(a.title)}</b>
      <span class="tag">${esc(a.reference)}</span>
      <ul class="acts">${a.actions.map(x=>`<li>${esc(x)}</li>`).join("")}</ul></div>`).join("")}
    </div>`).join("") || '<div class="empty">Already at target. 🎉</div>';
  return `<span class="back" onclick="_roadmapDomain=null;render()">← Choose domain</span>
    <div class="panel"><div class="flex"><h3 style="margin:0">${esc(d.domain)}</h3>
      ${ratingPill(d.current_rating)} → ${ratingPill(d.target_rating)}
      <span class="muted">score ${d.current_score}</span></div></div>
    <div class="panel" style="margin-top:1rem">${phases}</div>`;
};

window.groupRoadmap = async (kind, key)=>{
  const q = kind==="org"?"?org="+key : kind==="community"?"?community="+key : "";
  if(kind==="country"||kind==="region"){
    alert("Group roadmap is available per community or organisation.");
    return;
  }
  const d = await api("/roadmap/group"+q);
  const order = (d.priority_order||[]).map(c=>{
    const g=d.control_gaps[c];
    return `<div class="ctrlrow"><span class="lbl">${CTRL_LABEL[c]||c}</span>
      <span class="muted">missing ${g.missing} · partial ${g.partial} · done ${g.complete}</span></div>`;
  }).join("");
  $("#main").innerHTML = `<span class="back" onclick="render()">← Back</span>
    <div class="panel"><h3>Group roadmap — ${esc(d.scope)} (${d.domains} domains)</h3>
    ${order||'<div class="empty">No gaps.</div>'}</div>`;
};

views.runs = async () => {
  const runs = await api("/runs");
  let rows = runs.map(r=>`<tr><td><code>${esc(r.id)}</code></td>
    <td>${esc((r.started_at||'').slice(0,19).replace('T',' '))}</td>
    <td>${r.domains_done}/${r.domains_total}</td>
    <td class="muted">${esc(r.status)}</td>
    <td class="muted">${esc(r.trigger||'')}</td></tr>`).join("");
  return `<div class="panel"><h3>Run a scan</h3>
    <div class="flex"><input id="scan-in" placeholder="domain1.com, domain2.org"
      style="flex:1"><button class="btn" onclick="doScan()">Scan</button></div>
    <div class="muted" style="margin-top:.4rem">
      Comma or space separated. You can only scan domains you're assigned to.</div>
    </div>
    <div class="panel" style="margin-top:1rem"><h3>Recent runs</h3>
    <table><thead><tr><th>Run</th><th>Started</th><th>Progress</th>
    <th>Status</th><th>Trigger</th></tr></thead>
    <tbody>${rows||'<tr><td class="muted">No runs yet.</td></tr>'}</tbody></table></div>`;
};
window.doScan = async ()=>{
  const raw = $("#scan-in").value.split(/[\s,]+/).map(x=>x.trim()).filter(Boolean);
  if(!raw.length) return;
  try{
    const r = await api("/scan",{method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({domains:raw})});
    alert(`Queued ${r.domains} domain(s), run ${r.run_id}.`);
    render();
  }catch(e){ alert("Error: "+e.message); }
};

// ---- Router ---------------------------------------------------------
let _state = ["overview"];
function go(...args){ _state = args; render(); }
window.go = go;

async function render(){
  const [view,...args] = _state;
  document.querySelectorAll("#nav button").forEach(b=>
    b.classList.toggle("active", b.dataset.view===view ||
      (["domain"].includes(view)&&b.dataset.view==="domains") ||
      (["org"].includes(view)&&b.dataset.view==="organisations") ||
      (["groupreport"].includes(view)&&b.dataset.view==="groups")));
  const fn = views[view];
  if(!fn){ $("#main").innerHTML='<div class="empty">Unknown view</div>'; return; }
  $("#main").innerHTML = '<div class="empty">Loading…</div>';
  try{ $("#main").innerHTML = await fn(...args); }
  catch(e){ $("#main").innerHTML = `<div class="panel"><div class="empty">
    Error: ${esc(e.message)}</div></div>`; }
}
document.querySelectorAll("#nav button").forEach(b=>
  b.onclick=()=>go(b.dataset.view));

async function initGuidelines(){
  try{
    GUIDELINES = await api("/guidelines");
  }catch(e){ GUIDELINES = []; }
  const def = GUIDELINES.find(g=>g.is_default) || GUIDELINES[0];
  if(def) GUIDELINE = def.id;
  const sel = $("#gsel");
  if(sel){
    sel.innerHTML = GUIDELINES.map(g=>
      `<option value="${esc(g.id)}"${g.id===GUIDELINE?' selected':''}>${
        esc(g.name)}${g.has_data?'':' (no data)'}</option>`).join("")
      || `<option>${esc(GUIDELINE)}</option>`;
  }
}
(async ()=>{ await initGuidelines(); render(); })();
</script>
</body>
</html>
"""
