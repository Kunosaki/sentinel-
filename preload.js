const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('sentinel', {
  selectFiles: () => ipcRenderer.invoke('select-files'),
  scanFiles: (paths) => ipcRenderer.invoke('scan-files', paths),
  fullScan: () => ipcRenderer.invoke('full-scan'),
  deleteFile: (path) => ipcRenderer.invoke('quarantine-file', path),
  wipeFile: (path) => ipcRenderer.invoke('wipe-file', path),
  listQuarantine: () => ipcRenderer.invoke('list-quarantine'),
  restoreQuarantine: (path) => ipcRenderer.invoke('restore-quarantine', path),
  wipeQuarantine: (path) => ipcRenderer.invoke('wipe-quarantine', path),
  scanProcesses: () => ipcRenderer.invoke('scan-processes'),
  scanStartup: () => ipcRenderer.invoke('scan-startup'),
  onScanProgress: (cb) => {
    ipcRenderer.on('scan-progress', (_, data) => cb(data));
    ipcRenderer.on('scan-result', (_, data) => cb(data));
    ipcRenderer.on('scan-done', (_, data) => cb(data));
    ipcRenderer.on('scan-error', (_, data) => cb(data));
  },
  // Live Monitor
  startMonitor: () => ipcRenderer.invoke('monitor:start'),
  stopMonitor: () => ipcRenderer.invoke('monitor:stop'),
  onMonitorData: (cb) => {
    ipcRenderer.on('monitor-data', (_, data) => cb(data));
  },
});
