#!/usr/bin/env python3
"""
Binary String Translator - Flask Web App
Stateless architecture: scan → JSON → edit → patch → download
"""

import os, json, uuid, threading, time, base64, tempfile, zipfile
from io import BytesIO
from flask import Flask, request, jsonify, send_file, abort, Response

# ── Import core engine (strip tkinter imports) ──
import importlib, types, sys

# Stub tkinter trước khi import core
for mod in ['tkinter', 'tkinter.ttk', 'tkinter.filedialog', 'tkinter.messagebox']:
    sys.modules.setdefault(mod, types.ModuleType(mod))

import core_engine as core  # bin39.py stripped of tkinter đổi tên thành core.py
_INDEX_HTML = """<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>Binary String Translator</title>
<style>
:root {
  --bg:      #1e1e2e;
  --surface: #181825;
  --overlay: #313244;
  --muted:   #45475a;
  --text:    #cdd6f4;
  --subtext: #a6adc8;
  --blue:    #89b4fa;
  --green:   #a6e3a1;
  --red:     #f38ba8;
  --yellow:  #f9e2af;
  --cyan:    #74c7ec;
  --r:       8px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;min-height:100vh}
button{cursor:pointer;border:none;border-radius:var(--r);padding:7px 14px;font-size:13px;font-family:inherit;transition:.15s}
button:active{transform:scale(.97)}
.btn-primary{background:var(--blue);color:#1e1e2e;font-weight:600}
.btn-primary:hover{background:var(--cyan)}
.btn-secondary{background:var(--overlay);color:var(--text)}
.btn-secondary:hover{background:var(--muted)}
.btn-danger{background:var(--red);color:#1e1e2e;font-weight:600}
.btn-danger:hover{filter:brightness(1.1)}
.btn-success{background:var(--green);color:#1e1e2e;font-weight:600}
.btn-success:hover{filter:brightness(1.1)}
.btn-sm{padding:4px 10px;font-size:12px}
input,select,textarea{background:var(--overlay);color:var(--text);border:1px solid var(--muted);border-radius:var(--r);padding:7px 10px;font-size:13px;font-family:inherit;outline:none;width:100%}
input:focus,select:focus,textarea:focus{border-color:var(--blue)}
select option{background:var(--overlay)}

/* Layout */
.header{background:var(--surface);border-bottom:1px solid var(--overlay);padding:10px 16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.header h1{font-size:16px;color:var(--blue);white-space:nowrap}
.container{padding:12px 16px;max-width:1400px;margin:0 auto}

/* Cards */
.card{background:var(--surface);border-radius:var(--r);padding:14px;margin-bottom:12px;border:1px solid var(--overlay)}
.card-title{font-size:12px;color:var(--subtext);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px}

/* Upload zone */
.upload-zone{border:2px dashed var(--muted);border-radius:var(--r);padding:24px;text-align:center;cursor:pointer;transition:.2s}
.upload-zone:hover,.upload-zone.drag{border-color:var(--blue);background:rgba(137,180,250,.06)}
.upload-zone input{display:none}
.upload-zone .icon{font-size:32px;margin-bottom:8px}
.upload-zone p{color:var(--subtext);font-size:13px}
.upload-zone .filename{color:var(--green);font-weight:600;margin-top:6px;word-break:break-all}

/* Progress */
.progress-wrap{display:none;margin-top:10px}
.progress-bar-bg{background:var(--overlay);border-radius:20px;height:8px;overflow:hidden}
.progress-bar{background:var(--blue);height:8px;width:0;transition:.3s;border-radius:20px}
.progress-text{font-size:12px;color:var(--subtext);margin-top:4px;text-align:center}

/* Stats bar */
.stats-bar{display:flex;gap:12px;flex-wrap:wrap;align-items:center;padding:8px 0}
.stat-badge{background:var(--overlay);border-radius:20px;padding:3px 10px;font-size:12px;color:var(--subtext)}
.stat-badge span{color:var(--text);font-weight:600}

/* Toolbar */
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.toolbar input{max-width:200px}
.toolbar select{max-width:160px;width:auto}

/* Table */
.table-wrap{overflow-x:auto;border-radius:var(--r);border:1px solid var(--overlay)}
table{width:100%;border-collapse:collapse;font-size:13px}
thead th{background:var(--overlay);color:var(--blue);font-weight:600;padding:8px 10px;text-align:left;white-space:nowrap;position:sticky;top:0;z-index:2}
tbody tr{border-bottom:1px solid var(--overlay)}
tbody tr:hover{background:rgba(49,50,68,.5)}
tbody tr.translated td:first-child{border-left:3px solid var(--green)}
tbody tr.changed td:nth-child(6){color:var(--green)}
td{padding:6px 10px;vertical-align:middle}
td.center{text-align:center}
td.mono{font-family:monospace;font-size:12px;color:var(--subtext)}

/* Translated input in table */
.tr-input{background:transparent;border:1px solid transparent;padding:3px 6px;border-radius:4px;width:100%;color:var(--text);font-size:13px}
.tr-input:focus{background:var(--overlay);border-color:var(--blue)}
.byte-info{font-size:10px;display:block;margin-top:2px}
.byte-ok{color:var(--green)}
.byte-warn{color:var(--yellow)}
.byte-over{color:var(--red)}

/* Action buttons in table */
.act-btn{background:none;border:none;padding:2px 5px;border-radius:4px;font-size:14px;cursor:pointer;transition:.15s}
.act-btn:hover{background:var(--overlay)}
.act-copy{color:var(--blue)}
.act-tr{color:var(--cyan)}
.act-rb{color:var(--yellow)}

/* Format select in table */
.fmt-sel{background:var(--surface);border:1px solid var(--muted);color:var(--subtext);border-radius:4px;padding:2px 4px;font-size:11px;width:100%}

/* Checkbox */
.cb{width:16px;height:16px;cursor:pointer;accent-color:var(--blue)}

/* Pager */
.pager{display:flex;align-items:center;gap:10px;justify-content:center;padding:10px 0}
.page-info{color:var(--subtext);font-size:13px}

/* Toast */
.toast-container{position:fixed;bottom:20px;right:20px;display:flex;flex-direction:column;gap:8px;z-index:9999}
.toast{background:var(--overlay);border-radius:var(--r);padding:10px 16px;font-size:13px;max-width:320px;box-shadow:0 4px 20px rgba(0,0,0,.4);animation:fadein .2s}
.toast.ok{border-left:3px solid var(--green)}
.toast.err{border-left:3px solid var(--red)}
.toast.info{border-left:3px solid var(--blue)}
@keyframes fadein{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}

/* Section toggle */
.section-hidden{display:none}

/* Accent toggle */
.toggle-row{display:flex;align-items:center;gap:8px}
.toggle-label{font-size:13px;color:var(--text);cursor:pointer}

/* Mobile adjustments */
@media(max-width:600px){
  table{font-size:12px}
  thead th,td{padding:5px 6px}
  .toolbar{gap:6px}
  .toolbar input,.toolbar select{max-width:140px}
}
</style>
</head>
<body>

<div class="header">
  <h1>🔧 Binary String Translator</h1>
  <span style="color:var(--subtext);font-size:12px">Việt Hóa Game J2ME</span>
</div>

<div class="container">

  <!-- Upload Card -->
  <div class="card" id="card-upload">
    <div class="card-title">1. Chọn file JAR / ZIP</div>
    <div class="upload-zone" id="drop-zone" onclick="document.getElementById('jar-input').click()">
      <input type="file" id="jar-input" accept=".jar,.zip">
      <div class="icon">📦</div>
      <p>Bấm để chọn file hoặc kéo thả vào đây</p>
      <div class="filename" id="file-name-label"></div>
    </div>
    <div class="progress-wrap" id="scan-progress-wrap">
      <div class="progress-bar-bg"><div class="progress-bar" id="scan-bar"></div></div>
      <div class="progress-text" id="scan-text">Đang scan...</div>
    </div>
    <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn-primary" id="btn-scan" onclick="startScan()">🔍 Scan JAR</button>
    </div>
  </div>

  <!-- Results Card -->
  <div class="card section-hidden" id="card-results">
    <div class="card-title">2. Kết quả Scan</div>
    <div class="stats-bar" id="stats-bar"></div>

    <!-- Toolbar -->
    <div class="toolbar">
      <input type="text" id="search-input" placeholder="🔍 Tìm kiếm..." oninput="debounceFilter()">
      <input type="text" id="replace-input" placeholder="Thay bằng...">
      <button class="btn-secondary btn-sm" onclick="doReplaceAll()">Replace All</button>
      <select id="fmt-filter" onchange="applyFilter()">
        <option value="">Tất cả format</option>
      </select>
      <button class="btn-secondary btn-sm" onclick="clearFilter()">✕ Xóa filter</button>
    </div>

    <!-- Translate controls -->
    <div class="toolbar" style="margin-bottom:12px">
      <div class="toggle-row">
        <input type="checkbox" id="chk-accent" checked class="cb">
        <label class="toggle-label" for="chk-accent">Có dấu</label>
      </div>
      <button class="btn-secondary btn-sm" onclick="translatePage()">▶ Dịch trang này</button>
      <button class="btn-primary btn-sm" onclick="translateAll()">▶ Dịch tất cả</button>
      <button class="btn-danger btn-sm" id="btn-stop" style="display:none" onclick="stopTranslate()">■ Dừng</button>
      <span id="tr-status" style="color:var(--subtext);font-size:12px"></span>
    </div>

    <!-- Progress translate -->
    <div class="progress-wrap" id="tr-progress-wrap">
      <div class="progress-bar-bg"><div class="progress-bar" id="tr-bar"></div></div>
      <div class="progress-text" id="tr-text"></div>
    </div>

    <!-- Table -->
    <div class="table-wrap" style="margin-top:10px">
      <table id="strings-table">
        <thead>
          <tr>
            <th style="width:32px">✔</th>
            <th style="width:130px">File</th>
            <th style="width:140px">Format</th>
            <th style="width:70px">Offset</th>
            <th>Gốc (CN/VI)</th>
            <th style="width:28px"></th>
            <th>Đã dịch (có thể sửa)</th>
            <th style="width:28px"></th>
            <th style="width:28px"></th>
          </tr>
        </thead>
        <tbody id="table-body"></tbody>
      </table>
    </div>

    <!-- Pager -->
    <div class="pager">
      <button class="btn-secondary btn-sm" onclick="prevPage()">◀ Prev</button>
      <span class="page-info" id="page-info">Page 1 / 1</span>
      <button class="btn-secondary btn-sm" onclick="nextPage()">Next ▶</button>
    </div>
  </div>

  <!-- Patch Card -->
  <div class="card section-hidden" id="card-patch">
    <div class="card-title">3. Patch & Download</div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
      <button class="btn-success" onclick="doPatch()">🔧 Patch JAR & Download</button>
      <button class="btn-secondary btn-sm" onclick="exportJSON()">⬇ Export JSON</button>
      <label class="btn-secondary btn-sm" style="cursor:pointer">
        ⬆ Import JSON
        <input type="file" id="import-json-input" accept=".json" style="display:none" onchange="importJSON(event)">
      </label>
      <span id="patch-status" style="color:var(--subtext);font-size:12px"></span>
    </div>
  </div>

</div>

<!-- Toast container -->
<div class="toast-container" id="toasts"></div>

<script>
// ═══════════════════════════════════════════════════
// State
// ═══════════════════════════════════════════════════
let allStrings   = [];   // full list (serialised, with raw as base64)
let filtered     = [];   // filtered view
let currentPage  = 0;
const PAGE_SIZE  = 30;
let jarB64       = '';
let jarFilename  = '';
let stopFlag     = false;
let filterTimer  = null;
let jobId        = null;
let pollTimer    = null;

// Format labels for dropdown
const FMT_LABELS = {
  'len1_utf8':   '1B-len UTF-8',
  'len2be_utf8': '2B-len UTF-8 (Java)',
  'len2le_utf8': '2B-len UTF-8 (LE)',
  'len1_gbk':    '1B-len GBK',
  'len2be_gbk':  '2B-len GBK',
  'null_utf8':   'Null-term UTF-8',
  'null_gbk':    'Null-term GBK',
  'xse':         'XSE Script',
  'utf16_le':    'UTF-16 LE',
  'utf16_be':    'UTF-16 BE',
  'xml':         'XML',
};
const FMT_OPTIONS = [
  ['len1_utf8','1B-len UTF-8'],['len2be_utf8','2B-len UTF-8 (Java)'],
  ['len2le_utf8','2B-len UTF-8 (LE)'],['len1_gbk','1B-len GBK'],
  ['len2be_gbk','2B-len GBK'],['null_utf8','Null-term UTF-8'],
  ['null_gbk','Null-term GBK'],['utf16_le','UTF-16 LE'],
  ['utf16_be','UTF-16 BE'],['xml','XML'],
  ['len1_big5','BIG5 (1B-len)'],['len1_gb2312','GB2312 (1B-len)'],
];

// ═══════════════════════════════════════════════════
// File upload
// ═══════════════════════════════════════════════════
const dropZone = document.getElementById('drop-zone');
const jarInput = document.getElementById('jar-input');

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag'));
dropZone.addEventListener('drop', e => {
  e.preventDefault(); dropZone.classList.remove('drag');
  const file = e.dataTransfer.files[0];
  if (file) { jarInput.files = e.dataTransfer.files; onFileChosen(file); }
});
jarInput.addEventListener('change', () => {
  if (jarInput.files[0]) onFileChosen(jarInput.files[0]);
});

function onFileChosen(file) {
  document.getElementById('file-name-label').textContent = `📦 ${file.name} (${(file.size/1024).toFixed(1)} KB)`;
  jarFilename = file.name;
}

// ═══════════════════════════════════════════════════
// Scan
// ═══════════════════════════════════════════════════
async function startScan() {
  if (!jarInput.files[0]) { toast('Chọn file JAR trước!', 'err'); return; }
  const file = jarInput.files[0];
  setScanProgress(true, 0, 1, 'Đang upload...');
  document.getElementById('btn-scan').disabled = true;

  const fd = new FormData();
  fd.append('jar', file);

  try {
    const res = await fetch('/api/scan', { method: 'POST', body: fd });
    const data = await res.json();
    if (data.error) { toast(data.error, 'err'); setScanProgress(false); document.getElementById('btn-scan').disabled = false; return; }
    jobId = data.job_id;
    pollScanStatus();
  } catch(e) {
    toast('Lỗi kết nối: ' + e.message, 'err');
    setScanProgress(false);
    document.getElementById('btn-scan').disabled = false;
  }
}

function pollScanStatus() {
  if (!jobId) return;
  fetch(`/api/scan/status/${jobId}`)
    .then(r => r.json())
    .then(data => {
      if (data.error && data.error !== 'null') {
        if (data.status !== 'done') {
          toast('Lỗi scan: ' + data.error, 'err');
          setScanProgress(false);
          document.getElementById('btn-scan').disabled = false;
          return;
        }
      }
      if (data.status === 'scanning') {
        const pct = data.total > 0 ? (data.progress / data.total) * 100 : 0;
        setScanProgress(true, pct, 100, `Đang scan ${data.progress}/${data.total}...`);
        pollTimer = setTimeout(pollScanStatus, 400);
      } else if (data.status === 'done') {
        setScanProgress(false);
        document.getElementById('btn-scan').disabled = false;
        onScanDone(data);
      } else if (data.status === 'error') {
        toast('Lỗi scan: ' + data.error, 'err');
        setScanProgress(false);
        document.getElementById('btn-scan').disabled = false;
      } else {
        pollTimer = setTimeout(pollScanStatus, 400);
      }
    })
    .catch(() => { pollTimer = setTimeout(pollScanStatus, 800); });
}

function onScanDone(data) {
  allStrings = data.strings || [];
  jarB64     = data.jar_b64 || '';
  jarFilename = data.filename || jarFilename;

  // Build format filter dropdown
  const fmts = [...new Set(allStrings.map(s => s.fmt))];
  const sel = document.getElementById('fmt-filter');
  sel.innerHTML = '<option value="">Tất cả format</option>';
  fmts.forEach(f => {
    const opt = document.createElement('option');
    opt.value = f; opt.textContent = FMT_LABELS[f] || f;
    sel.appendChild(opt);
  });

  applyFilter();
  show('card-results'); show('card-patch');

  // Stats
  document.getElementById('stats-bar').innerHTML =
    `<div class="stat-badge">Tổng: <span>${allStrings.length}</span></div>` +
    (data.fmt_stats ? `<div class="stat-badge" style="color:var(--subtext);font-size:11px">${data.fmt_stats}</div>` : '');

  toast(`Scan xong! ${allStrings.length} strings`, 'ok');
}

function setScanProgress(show, val=0, max=100, text='') {
  const wrap = document.getElementById('scan-progress-wrap');
  wrap.style.display = show ? 'block' : 'none';
  document.getElementById('scan-bar').style.width = (val/max*100) + '%';
  document.getElementById('scan-text').textContent = text;
}

// ═══════════════════════════════════════════════════
// Filter / Search
// ═══════════════════════════════════════════════════
function debounceFilter() {
  clearTimeout(filterTimer);
  filterTimer = setTimeout(applyFilter, 180);
}

function applyFilter() {
  const q   = document.getElementById('search-input').value.toLowerCase().trim();
  const fmt = document.getElementById('fmt-filter').value;
  filtered = allStrings.filter(s => {
    if (fmt && s.fmt !== fmt) return false;
    if (q) return s.original.toLowerCase().includes(q) || (s.translated||'').toLowerCase().includes(q);
    return true;
  });
  currentPage = 0;
  renderTable();
}

function clearFilter() {
  document.getElementById('search-input').value = '';
  document.getElementById('fmt-filter').value   = '';
  filtered = allStrings.slice();
  currentPage = 0;
  renderTable();
}

function doReplaceAll() {
  const q = document.getElementById('search-input').value;
  const r = document.getElementById('replace-input').value;
  if (!q) { toast('Nhập từ cần tìm vào ô Search.', 'err'); return; }
  let count = 0;
  filtered.forEach(s => {
    if (s.translated && s.translated.includes(q)) {
      s.translated = s.translated.replaceAll(q, r);
      count++;
    }
  });
  renderTable();
  toast(`Đã replace ${count} strings.`, 'ok');
}

// ═══════════════════════════════════════════════════
// Table render
// ═══════════════════════════════════════════════════
function renderTable() {
  const tbody = document.getElementById('table-body');
  tbody.innerHTML = '';
  const total  = filtered.length;
  const pages  = Math.max(1, Math.ceil(total / PAGE_SIZE));
  if (currentPage >= pages) currentPage = pages - 1;
  document.getElementById('page-info').textContent = `Page ${currentPage+1} / ${pages} — ${total} strings`;

  const start = currentPage * PAGE_SIZE;
  const end   = Math.min(start + PAGE_SIZE, total);

  for (let i = start; i < end; i++) {
    const s   = filtered[i];
    const gidx = allStrings.indexOf(s);
    const isChanged = s.translated !== s.original;
    const tr = document.createElement('tr');
    if (isChanged) tr.classList.add('translated');

    // byte info
    const origBytes = atob(s.raw || '').length;

    tr.innerHTML = `
      <td class="center"><input type="checkbox" class="cb" ${s.enabled ? 'checked':''} onchange="toggleEnabled(${gidx},this.checked)"></td>
      <td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(s.jar_entry)}">${esc(basename(s.jar_entry))}</td>
      <td>
        <select class="fmt-sel" onchange="changeFmt(${gidx},this.value)">
          ${FMT_OPTIONS.map(([k,l])=>`<option value="${k}" ${s.fmt===k?'selected':''}>${l}</option>`).join('')}
        </select>
      </td>
      <td class="mono">0x${s.offset.toString(16).toUpperCase()}</td>
      <td>
        <span title="${esc(s.original)}">${esc(s.original.length>80?s.original.slice(0,80)+'…':s.original)}</span>
      </td>
      <td class="center"><button class="act-btn act-copy" title="Copy gốc" onclick="copyText(${gidx},'original')">⧉</button></td>
      <td style="min-width:200px">
        <input class="tr-input" value="${esc(s.translated||'')}" 
          oninput="updateTranslated(${gidx},this.value);updateByteInfo(this,${gidx})"
          onfocus="updateByteInfo(this,${gidx})"
          placeholder="Nhập bản dịch...">
        <span class="byte-info" id="bi-${gidx}"></span>
      </td>
      <td class="center"><button class="act-btn act-copy" title="Copy dịch" onclick="copyText(${gidx},'translated')">⧉</button></td>
      <td class="center">
        ${isChanged
          ? `<button class="act-btn act-rb" title="Rollback" onclick="rollback(${gidx})">↩</button>`
          : `<button class="act-btn act-tr" title="Dịch" onclick="translateOne(${gidx})">▶</button>`
        }
      </td>`;
    tbody.appendChild(tr);
  }
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function basename(p) { return p.replace(/.*[/\\\\]/,''); }

function updateByteInfo(input, gidx) {
  const s = allStrings[gidx];
  if (!s) return;
  const origBytes = atob(s.raw || '').length;
  const newBytes  = new TextEncoder().encode(input.value).length;
  const diff = newBytes - origBytes;
  const el   = document.getElementById('bi-' + gidx);
  if (!el) return;
  const cls  = diff > 4 ? 'byte-over' : (diff > 0 ? 'byte-warn' : 'byte-ok');
  el.className = 'byte-info ' + cls;
  el.textContent = `Gốc: ${origBytes}B → Dịch: ${newBytes}B [${diff>=0?'+':''}${diff}B]`;
}

// ═══════════════════════════════════════════════════
// Data mutations
// ═══════════════════════════════════════════════════
function toggleEnabled(gidx, val) {
  if (allStrings[gidx]) allStrings[gidx].enabled = val;
}

function updateTranslated(gidx, val) {
  if (allStrings[gidx]) allStrings[gidx].translated = val;
  // update row class
  const s = allStrings[gidx];
  if (!s) return;
  const fidx = filtered.indexOf(s);
  if (fidx < 0) return;
  const row = document.getElementById('table-body').rows[fidx - currentPage * PAGE_SIZE];
  if (row) {
    row.classList.toggle('translated', val !== s.original);
    // update rollback/translate button
    const btnTd = row.cells[row.cells.length-1];
    if (val !== s.original) {
      btnTd.innerHTML = `<button class="act-btn act-rb" title="Rollback" onclick="rollback(${gidx})">↩</button>`;
    } else {
      btnTd.innerHTML = `<button class="act-btn act-tr" title="Dịch" onclick="translateOne(${gidx})">▶</button>`;
    }
  }
}

function rollback(gidx) {
  const s = allStrings[gidx];
  if (!s) return;
  s.translated = s.original;
  renderTable();
}

function copyText(gidx, field) {
  const s = allStrings[gidx];
  if (!s) return;
  navigator.clipboard.writeText(s[field]||'').then(() => toast('Đã copy!','info'));
}

async function changeFmt(gidx, newFmt) {
  const s = allStrings[gidx];
  if (!s) return;
  s.fmt = newFmt;
  // Re-decode raw bytes
  try {
    const res = await fetch('/api/redecode', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ raw: s.raw, fmt: newFmt })
    });
    const data = await res.json();
    if (data.text) {
      s.original   = data.text;
      s.translated = data.text;
      renderTable();
      toast(`Re-decode [${newFmt}]: ${data.text.slice(0,40)}`, 'ok');
    } else {
      toast('Không decode được với format này.', 'err');
    }
  } catch(e) {
    toast('Lỗi re-decode: ' + e.message, 'err');
  }
}

// ═══════════════════════════════════════════════════
// Pager
// ═══════════════════════════════════════════════════
function prevPage() {
  if (currentPage > 0) { currentPage--; renderTable(); window.scrollTo(0,300); }
}
function nextPage() {
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  if (currentPage < pages-1) { currentPage++; renderTable(); window.scrollTo(0,300); }
}

// ═══════════════════════════════════════════════════
// Translation
// ═══════════════════════════════════════════════════
let translateAbort = false;

async function translateAll() {
  if (!allStrings.length) { toast('Chưa scan JAR.','err'); return; }
  const indices = allStrings.map((_,i)=>i);
  await runTranslate(allStrings, indices);
}

async function translatePage() {
  if (!filtered.length) return;
  const start   = currentPage * PAGE_SIZE;
  const end     = Math.min(start + PAGE_SIZE, filtered.length);
  const page    = filtered.slice(start, end);
  const indices = page.map(s => allStrings.indexOf(s)).filter(i => i>=0);
  await runTranslate(allStrings, indices);
}

async function translateOne(gidx) {
  const s = allStrings[gidx];
  if (!s) return;
  setTrProgress(true, 0, 1, 'Đang dịch...');
  try {
    const res = await fetch('/api/translate', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        strings: allStrings,
        indices: [gidx],
        accent:  document.getElementById('chk-accent').checked,
      })
    });
    const data = await res.json();
    if (data.error) { toast(data.error,'err'); setTrProgress(false); return; }
    (data.results||[]).forEach(r => { if (allStrings[r.idx]) allStrings[r.idx].translated = r.translated; });
    renderTable();
    toast('Dịch xong!','ok');
  } catch(e) {
    toast('Lỗi dịch: '+e.message,'err');
  }
  setTrProgress(false);
}

async function runTranslate(strings, indices) {
  translateAbort = false;
  document.getElementById('btn-stop').style.display = 'inline-block';
  const accent = document.getElementById('chk-accent').checked;
  const CHUNK  = 20;
  const total  = indices.length;
  let done = 0;

  for (let i = 0; i < indices.length; i += CHUNK) {
    if (translateAbort) break;
    const chunk = indices.slice(i, i + CHUNK);
    setTrProgress(true, done, total, `Đang dịch ${done}/${total}...`);
    try {
      const res = await fetch('/api/translate', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ strings, indices: chunk, accent })
      });
      const data = await res.json();
      if (data.error) { toast(data.error,'err'); break; }
      (data.results||[]).forEach(r => {
        if (strings[r.idx]) strings[r.idx].translated = r.translated;
      });
      done += chunk.length;
      setTrProgress(true, done, total, `Đang dịch ${done}/${total}...`);
      if (i % (CHUNK*3) === 0) renderTable();
    } catch(e) {
      toast('Lỗi dịch: '+e.message,'err');
      break;
    }
  }
  renderTable();
  setTrProgress(false);
  document.getElementById('btn-stop').style.display = 'none';
  document.getElementById('tr-status').textContent = `Dịch xong ${done} strings.`;
}

function stopTranslate() { translateAbort = true; }

function setTrProgress(show, val=0, max=1, text='') {
  document.getElementById('tr-progress-wrap').style.display = show ? 'block' : 'none';
  document.getElementById('tr-bar').style.width = (max>0 ? val/max*100 : 0) + '%';
  document.getElementById('tr-text').textContent = text;
}

// ═══════════════════════════════════════════════════
// Patch
// ═══════════════════════════════════════════════════
async function doPatch() {
  if (!jarB64) { toast('Chưa scan JAR.','err'); return; }
  const changed = allStrings.filter(s => s.enabled && s.translated !== s.original).length;
  if (changed === 0) { toast('Không có string nào thay đổi.','err'); return; }

  document.getElementById('patch-status').textContent = 'Đang patch...';
  try {
    const res = await fetch('/api/patch', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ jar_b64: jarB64, strings: allStrings, filename: jarFilename })
    });
    if (!res.ok) {
      const err = await res.json();
      toast('Lỗi patch: '+(err.error||res.statusText),'err');
      document.getElementById('patch-status').textContent = '';
      return;
    }
    const blob = await res.blob();
    const base = jarFilename.replace(/\\.[^.]+$/,'');
    const ext  = jarFilename.match(/\\.[^.]+$/)?.[0] || '.jar';
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = base + '_vi' + ext;
    a.click(); URL.revokeObjectURL(url);
    document.getElementById('patch-status').textContent = `Patch xong! ${changed} strings thay đổi.`;
    toast(`Đã patch ${changed} strings!`, 'ok');
  } catch(e) {
    toast('Lỗi: '+e.message,'err');
    document.getElementById('patch-status').textContent = '';
  }
}

// ═══════════════════════════════════════════════════
// JSON Export / Import
// ═══════════════════════════════════════════════════
function exportJSON() {
  if (!allStrings.length) { toast('Chưa có dữ liệu.','err'); return; }
  const data = JSON.stringify(allStrings, null, 2);
  const blob = new Blob([data], {type:'application/json'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = (jarFilename||'strings').replace(/\\.[^.]+$/,'') + '_strings.json';
  a.click(); URL.revokeObjectURL(url);
  toast('Đã export JSON.','ok');
}

function importJSON(e) {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = ev => {
    try {
      const data = JSON.parse(ev.target.result);
      if (!Array.isArray(data)) { toast('JSON không hợp lệ.','err'); return; }
      // Merge translated values vào allStrings theo jar_entry+offset
      const map = {};
      data.forEach(s => { map[s.jar_entry+'|'+s.offset] = s.translated; });
      allStrings.forEach(s => {
        const key = s.jar_entry+'|'+s.offset;
        if (map[key] !== undefined) s.translated = map[key];
      });
      applyFilter();
      toast(`Import OK — ${Object.keys(map).length} entries.`,'ok');
    } catch(err) {
      toast('Lỗi parse JSON: '+err.message,'err');
    }
  };
  reader.readAsText(file);
  e.target.value = '';
}

// ═══════════════════════════════════════════════════
// UI helpers
// ═══════════════════════════════════════════════════
function show(id) { document.getElementById(id).classList.remove('section-hidden'); }

function toast(msg, type='info') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.getElementById('toasts').appendChild(el);
  setTimeout(() => el.remove(), 3000);
}
</script>
</body>
</html>
"""


import logging, traceback as _tb
logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32 MB

@app.errorhandler(Exception)
def _handle_exc(e):
    tb = _tb.format_exc()
    _logger.error(f'ERROR: {tb}')
    return jsonify(error=str(e), trace=tb), 500

# ── In-memory job store (stateless per-request cho scan nhỏ, job store cho translate) ──
_jobs: dict = {}   # job_id → {'status','progress','total','strings','error'}
_jobs_lock = threading.Lock()

PAGE_SIZE = 30


# ────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────

def _serialise(items: list) -> list:
    """Convert raw bytes → base64 str để JSON-safe."""
    out = []
    for it in items:
        d = dict(it)
        if isinstance(d.get('raw'), (bytes, bytearray)):
            d['raw'] = base64.b64encode(d['raw']).decode()
        out.append(d)
    return out


def _deserialise(items: list) -> list:
    """Convert base64 str → bytes."""
    out = []
    for it in items:
        d = dict(it)
        if isinstance(d.get('raw'), str):
            try:
                d['raw'] = base64.b64decode(d['raw'])
            except Exception:
                d['raw'] = b''
        out.append(d)
    return out


def _fmt_stats(strings: list) -> str:
    from collections import Counter
    counts = Counter(s['fmt'] for s in strings)
    return ' | '.join(
        f"{core.FORMAT_LABELS.get(f, f)}: {c}"
        for f, c in counts.most_common()
    )


# ────────────────────────────────────────────────────────────
# Routes
# ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return Response(_INDEX_HTML, mimetype='text/html; charset=utf-8')


# ── Scan ──

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """Upload JAR + scan → trả về JSON strings."""
    if 'jar' not in request.files:
        return jsonify(error='Không có file JAR.'), 400
    f = request.files['jar']
    if not f.filename:
        return jsonify(error='Tên file rỗng.'), 400

    jar_bytes = f.read()
    if not jar_bytes:
        return jsonify(error='File rỗng.'), 400

    # Validate ZIP/JAR
    try:
        with zipfile.ZipFile(BytesIO(jar_bytes)) as _zf:
            pass
    except Exception:
        return jsonify(error='File không phải JAR/ZIP hợp lệ.'), 400

    job_id = str(uuid.uuid4())
    with _jobs_lock:
        _jobs[job_id] = {
            'status': 'scanning', 'progress': 0, 'total': 1,
            'strings': [], 'jar_b64': base64.b64encode(jar_bytes).decode(),
            'filename': f.filename, 'error': None,
        }

    def _run():
        try:
            results = []
            def cb(i, total, name):
                with _jobs_lock:
                    job = _jobs.get(job_id)
                    if job:
                        job['progress'] = i
                        job['total']    = total

            # Scan từ bytes (không cần file tạm)
            with zipfile.ZipFile(BytesIO(jar_bytes), 'r') as zf:
                all_entries = zf.namelist()
                _EXT_BLACKLIST = {
                    '.class', '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico',
                    '.mp3', '.ogg', '.wav', '.mid', '.aac', '.jar', '.zip',
                    '.gz', '.bz2', '.mf', '.sf', '.rsa', '.dsa',
                    '.map', '.palet', '.palette', '.pal', '.fnt', '.font',
                    '.tileset', '.tile', '.spr', '.sprite', '.anim',
                    '.idx', '.index', '.lut', '.raw',
                }
                _EXT_ALLOWLIST = {
                    '.bin', '.dat', '.res', '.pak', '.txt', '.ini', '.cfg',
                    '.xse', '.xs', '.scr', '.tbl', '.db', '.msg', '.arc',
                    '.xml', '.json', '.csv', '.lang', '.lng', '.str', '.string',
                    '.prop', '.properties', '.conf', '.config',
                }

                def _should_scan(name):
                    if name.endswith('/') or name.startswith('META-INF/'):
                        return False
                    ext = os.path.splitext(name)[1].lower()
                    if ext in _EXT_BLACKLIST:
                        return False
                    if not ext or ext in _EXT_ALLOWLIST:
                        return True
                    return True

                entries = [n for n in all_entries if _should_scan(n)]
                total = len(entries)
                seen_keys = set()

                for i, name in enumerate(entries):
                    with _jobs_lock:
                        job = _jobs.get(job_id)
                        if job:
                            job['progress'] = i + 1
                            job['total']    = total
                    try:
                        data = zf.read(name)
                        basename = os.path.basename(name)
                        if not core.is_structured_binary(data, basename):
                            continue
                        fmt, string_entries = core.extract_strings_from_binary(data, basename)
                        if not string_entries:
                            continue
                        for offset, text, raw in string_entries:
                            if not core._is_meaningful_string(text):
                                continue
                            key = (name, offset, fmt)
                            if key in seen_keys:
                                continue
                            seen_keys.add(key)
                            results.append({
                                'jar_entry':  name,
                                'offset':     offset,
                                'raw':        raw,
                                'fmt':        fmt,
                                'original':   text,
                                'translated': text,
                                'enabled':    True,
                            })
                    except Exception:
                        continue

            with _jobs_lock:
                job = _jobs.get(job_id)
                if job:
                    job['strings'] = _serialise(results)
                    job['status']  = 'done'
        except Exception as e:
            with _jobs_lock:
                job = _jobs.get(job_id)
                if job:
                    job['status'] = 'error'
                    job['error']  = str(e)

    threading.Thread(target=_run, daemon=True).start()
    return jsonify(job_id=job_id)


@app.route('/api/scan/status/<job_id>')
def api_scan_status(job_id):
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify(error='Job không tồn tại.'), 404
    resp = {
        'status':   job['status'],
        'progress': job['progress'],
        'total':    job['total'],
        'error':    job.get('error'),
    }
    if job['status'] == 'done':
        strings = job['strings']
        resp['count']    = len(strings)
        resp['fmt_stats'] = _fmt_stats(_deserialise(strings))
        resp['strings']  = strings   # full list
        resp['filename'] = job.get('filename', '')
        resp['jar_b64']  = job.get('jar_b64', '')  # trả về JAR để patch sau
    return jsonify(resp)


# ── Translate ──

@app.route('/api/translate', methods=['POST'])
def api_translate():
    """Dịch batch strings, trả về list translated."""
    body = request.get_json(silent=True) or {}
    strings  = _deserialise(body.get('strings', []))
    indices  = body.get('indices', list(range(len(strings))))
    accent   = body.get('accent', True)

    if not strings:
        return jsonify(error='Không có strings.'), 400

    results = []
    tr = core.get_translator()
    if tr is None:
        return jsonify(error='deep-translator chưa cài. pip install deep-translator'), 500

    for idx in indices:
        if idx < 0 or idx >= len(strings):
            continue
        item = strings[idx]
        src = item['original']
        if core.has_chinese(src):
            try:
                if src in core._translate_cache:
                    vi = core._translate_cache[src]
                else:
                    vi = tr.translate(src)
                    if vi:
                        core._translate_cache[src] = vi
                if vi and vi.strip():
                    if not accent:
                        try:
                            from unidecode import unidecode
                            vi = unidecode(vi)
                        except ImportError:
                            pass
                    item['translated'] = vi
            except Exception:
                pass
        results.append({'idx': idx, 'translated': item['translated']})
        time.sleep(0.01)

    return jsonify(results=results)


# ── Patch ──

@app.route('/api/patch', methods=['POST'])
def api_patch():
    """Nhận JAR (base64) + strings → trả về patched JAR download."""
    body = request.get_json(silent=True) or {}
    jar_b64  = body.get('jar_b64', '')
    strings  = _deserialise(body.get('strings', []))
    filename = body.get('filename', 'output.jar')

    if not jar_b64:
        return jsonify(error='Thiếu jar_b64.'), 400
    if not strings:
        return jsonify(error='Thiếu strings.'), 400

    try:
        jar_bytes = base64.b64decode(jar_b64)
    except Exception:
        return jsonify(error='jar_b64 không hợp lệ.'), 400

    # Đổi tên output
    base, ext = os.path.splitext(filename)
    out_name  = base + '_vi' + (ext or '.jar')

    try:
        # Gom replacements theo jar_entry
        entry_repl = {}
        for item in strings:
            if not item.get('enabled', True):
                continue
            if item['translated'] == item['original']:
                continue
            ent = item['jar_entry']
            if ent not in entry_repl:
                entry_repl[ent] = {}
            entry_repl[ent][item['offset']] = (
                item['translated'], item['raw'], item['fmt']
            )

        if not entry_repl:
            return jsonify(error='Không có string nào thay đổi.'), 400

        out_buf = BytesIO()
        with zipfile.ZipFile(BytesIO(jar_bytes), 'r') as zin:
            with zipfile.ZipFile(out_buf, 'w', zipfile.ZIP_DEFLATED) as zout:
                for name in zin.namelist():
                    data = zin.read(name)
                    if name in entry_repl:
                        first = next(iter(entry_repl[name].values()))
                        fmt = first[2]
                        try:
                            data = core.patch_binary(data, fmt, entry_repl[name])
                        except Exception as e:
                            print(f'Patch error {name}: {e}')
                    zout.writestr(zipfile.ZipInfo(name), data)

        out_buf.seek(0)
        return send_file(
            out_buf,
            mimetype='application/java-archive',
            as_attachment=True,
            download_name=out_name,
        )
    except Exception as e:
        return jsonify(error=f'Lỗi patch: {e}'), 500


# ── Format change / re-decode ──

@app.route('/api/redecode', methods=['POST'])
def api_redecode():
    """Re-decode raw bytes với format mới."""
    body    = request.get_json(silent=True) or {}
    raw_b64 = body.get('raw', '')
    new_fmt = body.get('fmt', '')
    if not raw_b64 or not new_fmt:
        return jsonify(error='Thiếu raw hoặc fmt.'), 400
    try:
        raw  = base64.b64decode(raw_b64)
        text = core._redecode_raw(raw, new_fmt)
        if text is None:
            return jsonify(error='Không decode được.'), 400
        return jsonify(text=text)
    except Exception as e:
        return jsonify(error=str(e)), 500


# ── Cleanup old jobs (> 30 phút) ──

def _cleanup_loop():
    while True:
        time.sleep(300)
        cutoff = time.time() - 1800
        with _jobs_lock:
            old = [k for k, v in _jobs.items()
                   if v.get('_ts', time.time()) < cutoff]
            for k in old:
                del _jobs[k]

threading.Thread(target=_cleanup_loop, daemon=True).start()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
