import crypto from 'crypto';
import type { ScanResult } from '../types.js';
import { escapeHtml } from './sanitize.js';

// Scanned files are untrusted input: evidence, file paths and even config
// values (threshold, labels) can be attacker-controlled via a pull request.
// Everything that reaches the page is escaped, the finding data is embedded as
// inert JSON rather than executable script, and a CSP limits execution to the
// single known script below.


/** JSON that is safe inside a <script> element: no "</script>", "<!--" or line separators. */
export function toScriptSafeJson(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

// Static client script. Kept free of interpolation so its CSP hash is stable.
const REPORT_SCRIPT = `
const DATA = JSON.parse(document.getElementById('hound-data').textContent);

function escHtml(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

const tbody = document.getElementById('tbody');
const emptyMsg = document.getElementById('empty-msg');
const shownCount = document.getElementById('shown-count');

function renderRows(findings){
  tbody.innerHTML = '';
  if(findings.length === 0){
    emptyMsg.style.display = '';
    shownCount.textContent = '0 shown';
    return;
  }
  emptyMsg.style.display = 'none';
  shownCount.textContent = findings.length + ' shown';

  findings.forEach(function(f, i){
    const dataRow = document.createElement('tr');
    dataRow.dataset.idx = i;
    dataRow.innerHTML =
      '<td class="id-cell">'+escHtml(f.id)+'</td>'+
      '<td><span class="sev-badge sev-'+escHtml(f.severity)+'">'+escHtml(f.severity.toUpperCase())+'</span></td>'+
      '<td class="file-cell"><code>'+escHtml(f.file.replace(/\\\\/g,'/').split('/').slice(-3).join('/'))+'</code></td>'+
      '<td>'+escHtml(f.lineStart)+'</td>'+
      '<td class="title-cell">'+escHtml(f.title)+'</td>';

    const expandRow = document.createElement('tr');
    expandRow.className = 'expand-row hidden';
    expandRow.innerHTML =
      '<td colspan="5"><div class="expand-inner">'+
        '<div class="meta-chips">'+
          '<span class="chip">Confidence: '+escHtml(f.confidence)+'</span>'+
          '<span class="chip">Risk points: '+escHtml(f.riskPoints)+'</span>'+
          '<span class="chip">Line '+escHtml(f.lineStart)+(f.lineEnd !== f.lineStart ? '-'+escHtml(f.lineEnd) : '')+'</span>'+
          (f.mitre ? '<a class="chip" href="https://attack.mitre.org/techniques/'+escHtml(f.mitre.replace('.','/'))+'\" target="_blank" rel="noopener noreferrer" style="color:var(--orange);border-color:#f9731640">MITRE '+escHtml(f.mitre)+'</a>' : '')+
          (f.owasp || []).map(function(o){ return '<span class="chip">OWASP '+escHtml(o)+'</span>'; }).join('')+
        '</div>'+
        '<div class="ev-label">Evidence</div>'+
        '<pre>'+escHtml(f.evidence)+'</pre>'+
        '<div class="rem-label">Remediation</div>'+
        '<div class="rem">'+escHtml(f.remediation)+'</div>'+
      '</div></td>';

    dataRow.addEventListener('click', function(){
      const isOpen = !expandRow.classList.contains('hidden');
      expandRow.classList.toggle('hidden', isOpen);
      dataRow.classList.toggle('expanded', !isOpen);
    });

    tbody.appendChild(dataRow);
    tbody.appendChild(expandRow);
  });
}

// Filter state
let activeSev = 'all';
let activeQuery = '';

function applyFilters(){
  const filtered = DATA.allFindings.filter(function(f){
    if(activeSev !== 'all' && f.severity !== activeSev) return false;
    if(activeQuery){
      const q = activeQuery.toLowerCase();
      if(!f.id.toLowerCase().includes(q) &&
         !f.title.toLowerCase().includes(q) &&
         !f.file.toLowerCase().includes(q) &&
         !(f.mitre && f.mitre.toLowerCase().includes(q)) &&
         !(f.owasp || []).some(function(o){ return o.toLowerCase().includes(q); })) return false;
    }
    return true;
  });
  renderRows(filtered);
}

// Severity filter buttons
document.getElementById('sev-filters').addEventListener('click', function(e){
  const btn = e.target.closest('.fbtn');
  if(!btn) return;
  activeSev = btn.dataset.sev;
  document.querySelectorAll('#sev-filters .fbtn').forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  applyFilters();
});

// Search
document.getElementById('search').addEventListener('input', function(e){
  activeQuery = e.target.value.trim();
  applyFilters();
});

renderRows(DATA.allFindings);
`;

const SCRIPT_HASH = crypto.createHash('sha256').update(REPORT_SCRIPT, 'utf8').digest('base64');

const CSP = [
  "default-src 'none'",
  `script-src 'sha256-${SCRIPT_HASH}'`,
  "style-src 'unsafe-inline'",
  "img-src data:",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

function scoreColor(label: string): string {
  if (label === 'critical') return '#f85149';
  if (label === 'high')     return '#f97316';
  if (label === 'medium')   return '#d29922';
  return '#3b82f6';
}

export function buildHtmlReport(result: ScanResult): string {
  const { repoScore, scoreLabel, allFindings, files, threshold, passed } = result;

  const critCount = allFindings.filter(f => f.severity === 'critical').length;
  const highCount  = allFindings.filter(f => f.severity === 'high').length;
  const medCount   = allFindings.filter(f => f.severity === 'medium').length;
  const lowCount   = allFindings.filter(f => f.severity === 'low').length;

  // SVG gauge: circle ring filled proportionally
  const radius = 52;
  const circ = 2 * Math.PI * radius;
  const dash = circ * (repoScore / 100);
  const gap  = circ - dash;
  const gaugeColor = scoreColor(scoreLabel);

  const data = toScriptSafeJson({ allFindings, files, repoScore, scoreLabel, threshold, passed });

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="${CSP}">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ContextHound Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0d1117;--surface:#161b22;--surface2:#21262d;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--orange:#f97316;--crit:#f85149;--high:#f97316;--med:#d29922;--low:#3b82f6}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;line-height:1.5;padding:24px}
a{color:var(--orange);text-decoration:none}
code{font-family:'Cascadia Code','Fira Code',monospace;font-size:12px}
h1{font-size:22px;font-weight:700;letter-spacing:-.5px}
h2{font-size:16px;font-weight:600;margin-bottom:12px;color:var(--muted)}

/* Header */
.header{display:flex;align-items:center;gap:32px;padding:20px 24px;background:var(--surface);border:1px solid var(--border);border-radius:12px;margin-bottom:24px;flex-wrap:wrap}
.logo{font-weight:800;font-size:20px;white-space:nowrap}
.logo .ctx{background:linear-gradient(135deg,#fdba74,#f97316,#c2410c);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.gauge-wrap{position:relative;width:130px;height:130px;flex-shrink:0}
.gauge-wrap svg{transform:rotate(-90deg)}
.gauge-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px}
.gauge-score{font-size:28px;font-weight:800;line-height:1}
.gauge-label{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.header-info{flex:1;min-width:200px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:6px;font-size:12px;font-weight:700;margin-bottom:10px}
.badge-pass{background:#1a3a1a;color:#3fb950;border:1px solid #238636}
.badge-fail{background:#3a1a1a;color:#f85149;border:1px solid #da3633}
.meta-row{font-size:12px;color:var(--muted)}

/* Summary cards */
.cards{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
.card{flex:1;min-width:120px;padding:14px 18px;background:var(--surface);border:1px solid var(--border);border-radius:10px}
.card-count{font-size:28px;font-weight:800;line-height:1}
.card-label{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-top:4px}

/* Controls */
.controls{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap;align-items:center}
.search-box{padding:7px 12px;background:var(--surface);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:13px;width:220px}
.search-box::placeholder{color:var(--muted)}
.search-box:focus{outline:none;border-color:#f97316}
.filter-group{display:flex;gap:6px;flex-wrap:wrap}
.fbtn{padding:4px 10px;border-radius:20px;font-size:12px;font-weight:500;border:1px solid var(--border);background:var(--surface2);color:var(--muted);cursor:pointer;transition:all .15s}
.fbtn:hover{color:var(--text);border-color:#555}
.fbtn.active{border-color:#f97316;background:#f9731618;color:#f97316}
.fbtn[data-sev="critical"].active{border-color:var(--crit);background:#f8514918;color:var(--crit)}
.fbtn[data-sev="high"].active{border-color:var(--high);background:#f9731618;color:var(--high)}
.fbtn[data-sev="medium"].active{border-color:var(--med);background:#d2992218;color:var(--med)}
.fbtn[data-sev="low"].active{border-color:var(--low);background:#3b82f618;color:var(--low)}
.count-label{font-size:12px;color:var(--muted);margin-left:4px}

/* Table */
.table-wrap{background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:24px}
table{width:100%;border-collapse:collapse}
thead th{padding:8px 14px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);text-align:left;background:var(--surface2);border-bottom:1px solid var(--border)}
tbody tr{border-bottom:1px solid var(--border);cursor:pointer;transition:background .1s}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:var(--surface2)}
tbody tr.expanded{background:var(--surface2)}
tbody td{padding:10px 14px;vertical-align:middle}
.sev-badge{display:inline-block;padding:2px 7px;border-radius:5px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}
.sev-critical{background:#f8514920;color:var(--crit);border:1px solid #f8514940}
.sev-high    {background:#f9731620;color:var(--high);border:1px solid #f9731640}
.sev-medium  {background:#d2992220;color:var(--med);border:1px solid #d2992240}
.sev-low     {background:#3b82f620;color:var(--low);border:1px solid #3b82f640}
.file-cell code{color:#58a6ff}
.id-cell{font-family:'Cascadia Code','Fira Code',monospace;font-size:12px;color:var(--muted)}
.title-cell{max-width:340px}
.expand-row td{padding:0;border-top:1px solid var(--border)}
.expand-row.hidden{display:none}
.expand-inner{padding:14px 18px;background:#0d1117;border-left:3px solid var(--orange)}
.expand-inner .ev-label{font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-bottom:4px}
.expand-inner pre{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;margin-bottom:12px}
.expand-inner .rem-label{font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-bottom:4px}
.expand-inner .rem{font-size:13px;color:#c9d1d9;line-height:1.6}
.expand-inner .meta-chips{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap}
.chip{padding:2px 8px;border-radius:4px;font-size:11px;background:var(--surface2);border:1px solid var(--border);color:var(--muted)}
.empty{padding:40px;text-align:center;color:var(--muted);font-size:14px}
.footer{font-size:11px;color:var(--muted);text-align:center;margin-top:20px}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div class="logo"><span class="ctx">Context</span>Hound</div>

  <div class="gauge-wrap">
    <svg width="130" height="130" viewBox="0 0 130 130">
      <circle cx="65" cy="65" r="${radius}" stroke="#21262d" stroke-width="12" fill="none"/>
      <circle cx="65" cy="65" r="${radius}" stroke="${gaugeColor}" stroke-width="12" fill="none"
        stroke-dasharray="${dash.toFixed(1)} ${gap.toFixed(1)}"
        stroke-linecap="round"/>
    </svg>
    <div class="gauge-center">
      <span class="gauge-score" style="color:${gaugeColor}">${escapeHtml(repoScore)}</span>
      <span class="gauge-label">${escapeHtml(scoreLabel)}</span>
    </div>
  </div>

  <div class="header-info">
    <div class="badge ${passed ? 'badge-pass' : 'badge-fail'}">
      ${passed ? '✓ PASSED' : '✗ FAILED'}
    </div>
    <div class="meta-row">
      Threshold: ${escapeHtml(threshold)} &nbsp;·&nbsp;
      ${allFindings.length} finding${allFindings.length !== 1 ? 's' : ''} in ${files.length} file${files.length !== 1 ? 's' : ''}
    </div>
  </div>
</div>

<!-- Summary cards -->
<div class="cards">
  <div class="card">
    <div class="card-count" style="color:var(--crit)">${critCount}</div>
    <div class="card-label">Critical</div>
  </div>
  <div class="card">
    <div class="card-count" style="color:var(--high)">${highCount}</div>
    <div class="card-label">High</div>
  </div>
  <div class="card">
    <div class="card-count" style="color:var(--med)">${medCount}</div>
    <div class="card-label">Medium</div>
  </div>
  <div class="card">
    <div class="card-count" style="color:var(--low)">${lowCount}</div>
    <div class="card-label">Low</div>
  </div>
</div>

<!-- Controls -->
<div class="controls">
  <input class="search-box" type="text" id="search" placeholder="Search rules, files, MITRE or OWASP IDs…">
  <div class="filter-group" id="sev-filters">
    <button class="fbtn active" data-sev="all">All</button>
    <button class="fbtn" data-sev="critical">Critical</button>
    <button class="fbtn" data-sev="high">High</button>
    <button class="fbtn" data-sev="medium">Medium</button>
    <button class="fbtn" data-sev="low">Low</button>
  </div>
  <span class="count-label" id="shown-count">${allFindings.length} shown</span>
</div>

<!-- Table -->
<div class="table-wrap">
  <table id="findings-table">
    <thead>
      <tr>
        <th>ID</th>
        <th>Severity</th>
        <th>File</th>
        <th>Line</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>
  <div class="empty" id="empty-msg" style="display:none">No findings match your filters.</div>
</div>

<div class="footer">
  Generated by <strong>ContextHound</strong> &nbsp;·&nbsp; Static analysis only &nbsp;·&nbsp; No data left your machine
</div>

<script type="application/json" id="hound-data">${data}</script>
<script>${REPORT_SCRIPT}</script>
</body>
</html>`;
}
