const tabScan = document.getElementById('tabScan');
const tabQuarantine = document.getElementById('tabQuarantine');
const scanView = document.getElementById('scanView');
const quarantineView = document.getElementById('quarantineView');
const dropZone = document.getElementById('dropZone');
const browseBtn = document.getElementById('browseBtn');
const fullScanBtn = document.getElementById('fullScanBtn');
const resultsList = document.getElementById('resultsList');
const progressContainer = document.getElementById('progressContainer');
const progressFill = document.getElementById('progressFill');
const progressText = document.getElementById('progressText');
const statTotal = document.getElementById('statTotal');
const statSafe = document.getElementById('statSafe');
const statWarn = document.getElementById('statWarn');
const statDanger = document.getElementById('statDanger');
const modalOverlay = document.getElementById('modalOverlay');
const modalFilename = document.getElementById('modalFilename');
const modalFindings = document.getElementById('modalFindings');
const modalIgnore = document.getElementById('modalIgnore');
const modalTrash = document.getElementById('modalTrash');
const modalWipe = document.getElementById('modalWipe');
const themeToggle = document.getElementById('themeToggle');
const quarantineList = document.getElementById('quarantineList');
const qCount = document.getElementById('qCount');
const qSize = document.getElementById('qSize');

let dangerQueue = [];
let currentModalFile = null;
let isScanning = false;
let scanResults = [];

themeToggle.addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme');
  document.documentElement.setAttribute('data-theme', current === 'dark' ? 'light' : 'dark');
});

tabScan.addEventListener('click', () => {
  tabScan.classList.add('active');
  tabQuarantine.classList.remove('active');
  scanView.style.display = 'flex';
  quarantineView.style.display = 'none';
});

tabQuarantine.addEventListener('click', () => {
  tabQuarantine.classList.add('active');
  tabScan.classList.remove('active');
  scanView.style.display = 'none';
  quarantineView.style.display = 'flex';
  loadQuarantine();
});

dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => { dropZone.classList.remove('drag-over'); });
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const files = Array.from(e.dataTransfer.files).map(f => f.path);
  if (files.length) startScan(files);
});
dropZone.addEventListener('click', () => selectAndScan());
browseBtn.addEventListener('click', (e) => { e.stopPropagation(); selectAndScan(); });
fullScanBtn.addEventListener('click', (e) => { e.stopPropagation(); startFullScan(); });

window.sentinel.onScanProgress((data) => {
  if (data.type === 'progress') {
    const pct = data.total > 0 ? Math.min(99, Math.round((data.completed / data.total) * 100)) : 0;
    progressFill.style.width = pct + '%';
    progressText.textContent = `${data.completed} / ${data.total} files — ${data.path || ''}`;
  } else if (data.type === 'result') {
    scanResults.push(data);
    addResultItem(data);
  } else if (data.type === 'done') {
    progressFill.style.width = '100%';
    progressText.textContent = `Done — ${data.total} files scanned`;
    isScanning = false;
    setTimeout(() => { progressContainer.style.display = 'none'; }, 2000);
    updateStats();
    checkDangerFiles(scanResults);
  } else if (data.type === 'scan-error') {
    progressText.textContent = 'Error: ' + data.substring(0, 60);
  }
});

async function selectAndScan() {
  const paths = await window.sentinel.selectFiles();
  if (paths.length) startScan(paths);
}

async function startScan(paths) {
  if (isScanning) return;
  isScanning = true;
  scanResults = [];
  resultsList.innerHTML = '';
  progressContainer.style.display = 'flex';
  progressFill.style.width = '0%';
  progressText.textContent = 'Scanning...';
  statTotal.textContent = '0';
  statSafe.textContent = '0';
  statWarn.textContent = '0';
  statDanger.textContent = '0';

  const result = await window.sentinel.scanFiles(paths);
  if (!result.success) {
    resultsList.innerHTML = `<div class="empty-state"><p>Scan failed: ${result.error}</p></div>`;
    progressContainer.style.display = 'none';
    isScanning = false;
  }
}

async function startFullScan() {
  if (isScanning) return;
  isScanning = true;
  scanResults = [];
  resultsList.innerHTML = '';
  progressContainer.style.display = 'flex';
  progressFill.style.width = '0%';
  progressText.textContent = 'Scanning entire computer...';
  statTotal.textContent = '0';
  statSafe.textContent = '0';
  statWarn.textContent = '0';
  statDanger.textContent = '0';

  const result = await window.sentinel.fullScan();
  if (!result.success) {
    resultsList.innerHTML = `<div class="empty-state"><p>Full scan failed: ${result.error}</p></div>`;
    progressContainer.style.display = 'none';
    isScanning = false;
  }
}

function addResultItem(r) {
  const existing = resultsList.querySelector('.empty-state');
  if (existing) existing.remove();

  const severity = r.maxSeverity === 'high' || r.maxSeverity === 'critical' ? 'danger'
                 : r.maxSeverity === 'medium' ? 'warn'
                 : r.maxSeverity === 'low' ? 'warn' : 'safe';

  const item = document.createElement('div');
  item.className = 'result-item';
  item.dataset.path = r.path;
  item.innerHTML = `
    <span class="result-icon ${severity}"></span>
    <div class="result-info">
      <div class="result-name">${esc(r.filename)}</div>
      <div class="result-path">${esc(r.path)}</div>
      ${r.findings.length ? `<div class="result-findings">${r.findings.slice(0, 3).map(f =>
        `<span class="finding-tag">${esc(f.title)}</span>`
      ).join('')}${r.findings.length > 3 ? `<span class="finding-tag">+${r.findings.length - 3}</span>` : ''}</div>` : ''}
    </div>
    <span class="result-badge ${severity}">${r.maxSeverity}</span>
  `;
  resultsList.appendChild(item);
}

function updateStats() {
  let total = 0, safe = 0, warn = 0, danger = 0;
  scanResults.forEach(r => {
    total++;
    if (r.maxSeverity === 'high' || r.maxSeverity === 'critical') danger++;
    else if (r.maxSeverity === 'medium') warn++;
    else safe++;
  });
  statTotal.textContent = total;
  statSafe.textContent = safe;
  statWarn.textContent = warn;
  statDanger.textContent = danger;
}

function checkDangerFiles(results) {
  dangerQueue = results.filter(r =>
    r.maxSeverity === 'high' || r.maxSeverity === 'critical'
  );
  if (dangerQueue.length) showNextDanger();
}

function showNextDanger() {
  if (!dangerQueue.length) { modalOverlay.classList.remove('active'); return; }
  const file = dangerQueue.shift();
  currentModalFile = file;
  modalFilename.textContent = file.path;
  modalFindings.innerHTML = file.findings.map(f =>
    `<div class="modal-finding"><div class="modal-finding-title">${esc(f.title)}</div><div class="modal-finding-desc">${esc(f.description)}</div></div>`
  ).join('');
  modalOverlay.classList.add('active');
}

modalIgnore.addEventListener('click', () => {
  modalOverlay.classList.remove('active');
  showNextDanger();
});

modalTrash.addEventListener('click', async () => {
  if (currentModalFile) {
    await window.sentinel.deleteFile(currentModalFile.path);
    markResult(currentModalFile.path, 'quarantined', 'info');
  }
  modalOverlay.classList.remove('active');
  showNextDanger();
});

modalWipe.addEventListener('click', async () => {
  if (currentModalFile) {
    await window.sentinel.wipeFile(currentModalFile.path);
    markResult(currentModalFile.path, 'wiped', 'info');
  }
  modalOverlay.classList.remove('active');
  showNextDanger();
});

function markResult(path, label, cls) {
  const items = resultsList.querySelectorAll('.result-item');
  items.forEach(item => {
    if (item.dataset.path === path) {
      item.style.opacity = '0.3';
      const badge = item.querySelector('.result-badge');
      badge.textContent = label;
      badge.className = `result-badge ${cls}`;
    }
  });
}

async function loadQuarantine() {
  const files = await window.sentinel.listQuarantine();
  qCount.textContent = files.length;
  let totalSize = 0;
  files.forEach(f => totalSize += f.size);

  const units = ['B', 'KB', 'MB', 'GB'];
  let sizeStr = totalSize + ' B';
  let si = totalSize;
  for (const u of units) {
    if (si < 1024) { sizeStr = si.toFixed(1) + ' ' + u; break; }
    si /= 1024;
  }
  qSize.textContent = sizeStr;

  quarantineList.innerHTML = '';
  if (!files.length) {
    quarantineList.innerHTML = '<div class="empty-state"><p>No files in quarantine</p></div>';
    return;
  }

  files.forEach(f => {
    const item = document.createElement('div');
    item.className = 'q-item';
    item.innerHTML = `
      <span class="result-icon danger"></span>
      <div class="q-info">
        <div class="q-name">${esc(f.name)}</div>
        <div class="q-meta">${(f.size / 1024).toFixed(1)} KB &middot; ${new Date(f.date).toLocaleString()}</div>
      </div>
      <div class="q-actions">
        <button class="q-btn restore" data-path="${esc(f.path)}">Restore</button>
        <button class="q-btn delete" data-path="${esc(f.path)}">Delete</button>
      </div>
    `;
    quarantineList.appendChild(item);

    item.querySelector('.q-btn.restore').addEventListener('click', async () => {
      const r = await window.sentinel.restoreQuarantine(f.path);
      if (r.success) {
        item.remove();
        qCount.textContent = parseInt(qCount.textContent) - 1;
      }
    });

    item.querySelector('.q-btn.delete').addEventListener('click', async () => {
      const r = await window.sentinel.wipeQuarantine(f.path);
      if (r.success) {
        item.remove();
        qCount.textContent = parseInt(qCount.textContent) - 1;
      }
    });
  });
}

function esc(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}
