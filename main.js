const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn, execSync } = require('child_process');
const os = require('os');

// Live monitor state
let monitorInterval = null;
let watchedDirs = [];

let mainWindow;

const QUARANTINE_DIR = path.join(os.homedir(), 'SentinelQuarantine');

function createWindow() {
  const isMac = process.platform === 'darwin';
  mainWindow = new BrowserWindow({
    width: 960, height: 680,
    titleBarStyle: isMac ? 'hiddenInset' : 'hidden',
    backgroundColor: '#f5f5f7',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });

function send(channel, data) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, data);
  }
}

function scanFiles(filePaths) {
  return new Promise((resolve, reject) => {
    const scannerPath = path.join(__dirname, 'scan_cli.py');
    const proc = spawn('python', [scannerPath, ...filePaths]);

    const results = [];
    let buffer = '';
    let doneSent = false;

    proc.stdout.on('data', (data) => {
      buffer += data.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.type === 'result') {
            results.push(obj);
            send('scan-result', obj);
          } else if (obj.type === 'progress') {
            send('scan-progress', obj);
          }
        } catch {}
      }
    });

    proc.stderr.on('data', (data) => {
      send('scan-error', { type: 'error', message: data.toString().trim() });
    });

    proc.on('close', (code) => {
      if (buffer.trim()) {
        try {
          const obj = JSON.parse(buffer.trim());
          if (obj.type === 'result') results.push(obj);
        } catch {}
      }
      if (!doneSent) {
        doneSent = true;
        send('scan-done', { total: results.length });
      }
      if (code !== 0 && results.length === 0) {
        reject(new Error('Scanner failed'));
      } else {
        resolve(results);
      }
    });

    proc.on('error', (err) => {
      send('scan-error', { type: 'error', message: err.message });
      reject(err);
    });
  });
}

function getDrives() {
  const drives = [];
  for (let i = 65; i <= 90; i++) {
    const letter = String.fromCharCode(i);
    const root = letter + ':\\';
    try {
      fs.accessSync(root);
      drives.push(root);
    } catch {}
  }
  return drives;
}

fs.mkdirSync(QUARANTINE_DIR, { recursive: true });

ipcMain.handle('select-files', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile', 'multiSelections'],
  });
  return result.canceled ? [] : result.filePaths;
});

ipcMain.handle('scan-files', async (_, filePaths) => {
  try {
    const results = await scanFiles(filePaths);
    return { success: true, results };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('full-scan', async () => {
  try {
    const drives = getDrives();
    const results = await scanFiles(drives);
    return { success: true, results };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('quarantine-file', async (_, filePath) => {
  try {
    const basename = path.basename(filePath);
    const dest = path.join(QUARANTINE_DIR, basename);
    let finalDest = dest;
    let counter = 1;
    while (fs.existsSync(finalDest)) {
      const ext = path.extname(basename);
      const name = path.basename(basename, ext);
      finalDest = path.join(QUARANTINE_DIR, `${name}_${counter}${ext}`);
      counter++;
    }
    fs.renameSync(filePath, finalDest);
    return { success: true, quarantinedPath: finalDest };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('wipe-file', async (_, filePath) => {
  try {
    const fd = fs.openSync(filePath, 'r+');
    const size = fs.statSync(filePath).size;
    const buf = Buffer.alloc(4096);
    let written = 0;
    while (written < size) {
      const chunk = Math.min(4096, size - written);
      fs.writeSync(fd, buf, 0, chunk, written);
      written += chunk;
    }
    fs.closeSync(fd);
    fs.unlinkSync(filePath);
    return { success: true };
  } catch (e) {
    try { fs.unlinkSync(filePath); return { success: true }; }
    catch { return { success: false, error: e.message }; }
  }
});

ipcMain.handle('list-quarantine', async () => {
  try {
    const files = fs.readdirSync(QUARANTINE_DIR).map(name => {
      const fullPath = path.join(QUARANTINE_DIR, name);
      const stat = fs.statSync(fullPath);
      return { name, path: fullPath, size: stat.size, date: stat.mtime };
    });
    return files;
  } catch { return []; }
});

ipcMain.handle('restore-quarantine', async (_, filePath) => {
  try {
    const originalName = path.basename(filePath);
    const dest = path.join(os.homedir(), 'Desktop', originalName);
    fs.renameSync(filePath, dest);
    return { success: true, restoredPath: dest };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('wipe-quarantine', async (_, filePath) => {
  try {
    fs.unlinkSync(filePath);
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// === PROCESS SCANNING ===
ipcMain.handle('scan-processes', async () => {
  const procPaths = [];
  try {
    const out = execSync('wmic process get ExecutablePath /format:csv 2>nul', { encoding: 'utf8', timeout: 5000 });
    const lines = out.split('\n').filter(l => l.trim() && !l.includes('ExecutablePath'));
    for (const line of lines) {
      const parts = line.split(',');
      const p = parts[parts.length - 1]?.trim();
      if (p && fs.existsSync(p)) procPaths.push(p);
    }
  } catch {}
  // Deduplicate
  const unique = [...new Set(procPaths)];
  if (unique.length === 0) return { success: true, results: [] };
  return await scanFiles(unique).then(r => ({ success: true, results: r })).catch(e => ({ success: false, error: e.message }));
});

// === STARTUP SCANNING ===
ipcMain.handle('scan-startup', async () => {
  const startupPaths = [];

  // Registry Run keys
  const regKeys = [
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  ];
  for (const key of regKeys) {
    try {
      const out = execSync(`reg query "${key}" 2>nul`, { encoding: 'utf8', timeout: 3000 });
      const lines = out.split('\n').filter(l => l.trim() && !l.startsWith('HKEY') && !l.includes('(Default)'));
      for (const line of lines) {
        const m = line.match(/"([^"]+\.(exe|dll|bat|cmd|ps1|vbs|js|lnk))"/i);
        if (m) {
          const p = m[1].replace(/%([^%]+)%/g, (_, k) => process.env[k] || '');
          if (fs.existsSync(p)) startupPaths.push(p);
        }
      }
    } catch {}
  }

  // Startup folders
  const startupFolders = [
    path.join(os.homedir(), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
    path.join(process.env.ALLUSERSPROFILE || 'C:\\ProgramData', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
  ];
  for (const folder of startupFolders) {
    try {
      if (fs.existsSync(folder)) {
        for (const f of fs.readdirSync(folder)) {
          const full = path.join(folder, f);
          if (fs.statSync(full).isFile()) startupPaths.push(full);
        }
      }
    } catch {}
  }

  const unique = [...new Set(startupPaths)];
  if (unique.length === 0) return { success: true, results: [] };
  return await scanFiles(unique).then(r => ({ success: true, results: r })).catch(e => ({ success: false, error: e.message }));
});

// === LIVE MONITOR ===
const MONITOR_INTERVAL = 2000;
const watchedPaths = [
  os.tmpdir(),
  path.join(os.homedir(), 'AppData', 'Local', 'Temp'),
  path.join(os.homedir(), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
  process.env.ALLUSERSPROFILE ? path.join(process.env.ALLUSERSPROFILE, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup') : null,
  path.join(os.homedir(), 'Desktop'),
].filter(Boolean);

let prevProcesses = new Map();

function getRunningProcesses() {
  try {
    const out = execSync('wmic process get ProcessId,Name,ExecutablePath,WorkingSetSize /FORMAT:CSV 2>nul', { encoding: 'utf8', timeout: 3000 });
    const lines = out.split('\n').filter(l => l.trim() && !l.startsWith('Node') && !l.startsWith('"Node') && !l.includes('PSComputerName'));
    const procs = [];
    for (const line of lines) {
      const parts = line.split(',');
      if (parts.length >= 4) {
        const pid = parts[0].replace(/"/g, '').trim();
        const name = parts[1].replace(/"/g, '').trim();
        const exe = parts[2].replace(/"/g, '').trim();
        const ws = parseInt(parts[3].replace(/"/g, '').trim()) || 0;
        if (pid && name) procs.push({ pid, name, exe, mem: ws, memMB: Math.round(ws / (1024 * 1024) * 10) / 10 });
      }
    }
    return procs;
  } catch { return []; }
}

function getNetworkConnections() {
  try {
    const out = execSync('netstat -ano | findstr "ESTABLISHED" 2>nul', { encoding: 'utf8', timeout: 3000 });
    const lines = out.split('\n').filter(l => l.trim());
    const conns = [];
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 5) {
        const local = parts[1];
        const remote = parts[2];
        const pid = parts[4];
        conns.push({ local, remote, pid });
      }
    }
    return conns;
  } catch { return []; }
}

function startMonitor() {
  if (monitorInterval) return;

  // Watch directories for file changes
  for (const dir of watchedPaths) {
    try {
      if (!fs.existsSync(dir)) continue;
      const watcher = fs.watch(dir, { recursive: false }, (eventType, filename) => {
        if (!filename) return;
        const fullPath = path.join(dir, filename);
        send('monitor-data', {
          type: 'file',
          event: eventType,
          path: fullPath,
          filename,
          time: Date.now(),
        });
      });
      watchedDirs.push(watcher);
    } catch {}
  }

  // Poll processes for changes
  const now = new Date();
  const initial = getRunningProcesses();
  for (const p of initial) {
    prevProcesses.set(p.pid, { ...p, firstSeen: now });
  }

  send('monitor-data', { type: 'snapshot', processes: initial, time: Date.now() });

  monitorInterval = setInterval(() => {
    const current = getRunningProcesses();
    const currentPids = new Set(current.map(p => p.pid));
    const prevPids = new Set(prevProcesses.keys());

    // New processes
    for (const p of current) {
      if (!prevProcesses.has(p.pid)) {
        p.firstSeen = Date.now();
        prevProcesses.set(p.pid, p);
        send('monitor-data', {
          type: 'process-new',
          process: p,
          time: Date.now(),
        });
      } else {
        const old = prevProcesses.get(p.pid);
        const memDelta = p.mem - old.mem;
        if (Math.abs(memDelta) > 1024 * 1024) {
          prevProcesses.set(p.pid, p);
        }
      }
    }

    // Terminated processes
    for (const pid of prevPids) {
      if (!currentPids.has(pid)) {
        const old = prevProcesses.get(pid);
        prevProcesses.delete(pid);
        send('monitor-data', {
          type: 'process-end',
          process: old,
          time: Date.now(),
        });
      }
    }

    // Network snapshot
    const connections = getNetworkConnections();
    send('monitor-data', { type: 'network', connections, time: Date.now() });

    // Process list snapshot
    send('monitor-data', { type: 'process-list', processes: current, time: Date.now() });
  }, MONITOR_INTERVAL);
}

function stopMonitor() {
  if (monitorInterval) {
    clearInterval(monitorInterval);
    monitorInterval = null;
  }
  for (const w of watchedDirs) {
    try { w.close(); } catch {}
  }
  watchedDirs = [];
  prevProcesses.clear();
}

ipcMain.handle('monitor:start', async () => {
  startMonitor();
  return { success: true };
});

ipcMain.handle('monitor:stop', async () => {
  stopMonitor();
  return { success: true };
});
