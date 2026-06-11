const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn, execSync } = require('child_process');
const os = require('os');

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
