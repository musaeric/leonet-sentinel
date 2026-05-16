const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('sentinel', {
  getAgentId:   () => ipcRenderer.invoke('get-agent-id'),
  openExternal: (url) => ipcRenderer.invoke('open-external', url),
  isElectron:   true,
});
