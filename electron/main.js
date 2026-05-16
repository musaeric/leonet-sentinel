// LeoNet Sentinel — Electron Desktop Shell
const { app, BrowserWindow, Tray, Menu, nativeImage, shell, ipcMain, dialog } = require('electron');
const path = require('path');
const os   = require('os');

const isDev   = process.env.SENTINEL_DEV === 'true';
const PORT    = process.env.PORT || 3001;
const DEVURL  = 'http://localhost:5173';
const PRODURL = `http://localhost:${PORT}`;

let mainWindow = null;
let tray       = null;
let server     = null;

// ── Server Startup ────────────────────────────────────────────────────────────
function startServer() {
  server = require('../server/index');
  server.httpServer.listen(PORT, () => {
    console.log(`[Sentinel] Server on port ${PORT}`);
  });
  server.startMonitoring();
}

// ── Create Window ─────────────────────────────────────────────────────────────
function createWindow() {
  mainWindow = new BrowserWindow({
    width:           1280,
    height:          820,
    minWidth:        800,
    minHeight:       600,
    title:           'LeoNet Sentinel',
    backgroundColor: '#050A14',
    titleBarStyle:   process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: {
      preload:          path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration:  false,
    },
    show: false,
  });

  const url = isDev ? DEVURL : PRODURL;

  // Wait for server to be ready before loading
  const tryLoad = (attempts = 0) => {
    mainWindow.loadURL(url).catch(() => {
      if (attempts < 15) setTimeout(() => tryLoad(attempts + 1), 500);
    });
  };

  setTimeout(() => tryLoad(), isDev ? 2000 : 1200);

  mainWindow.once('ready-to-show', () => mainWindow.show());
  mainWindow.on('close', e => {
    if (process.platform === 'darwin') { e.preventDefault(); mainWindow.hide(); }
  });
}

// ── System Tray ───────────────────────────────────────────────────────────────
function createTray() {
  // Minimal icon (16x16 PNG as buffer)
  const iconBuffer = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSFlz' +
    'AAALEwAACxMBAJqcGAAAAmZJREFUOI1jYBgFgx8wMjD8Z2BgYGBkYGBg+M/AwMDIwMDA8J+BgYGB' +
    'gYGBgf8/AwMDAwMDA8N/BgYGBgYGBgb+/wwMDAwMDAwM/P8ZGBgYGBgYGPj/MzAwMDAwMDD8Z2Bg' +
    'YGBgYGDg/8/AwMDAwMDA8J+BgYGBgYGBgf8/AwMDAwMDAwP/GRgYGBgYGBj4/zMwMDAwMDAwMDAw' +
    'MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=',
    'base64'
  );
  let icon;
  try { icon = nativeImage.createFromBuffer(iconBuffer); }
  catch { icon = nativeImage.createEmpty(); }

  tray = new Tray(icon);
  tray.setToolTip('LeoNet Sentinel — Active');

  const rebuild = () => {
    const threats = server?.cfg ? 0 : 0;
    tray.setContextMenu(Menu.buildFromTemplate([
      { label: '🦁 LeoNet Sentinel', enabled: false },
      { label: `Agent: ${os.hostname()}`,    enabled: false },
      { label: `Status: Online`, enabled: false },
      { type: 'separator' },
      { label: 'Open Dashboard', click: () => { mainWindow?.show(); mainWindow?.focus(); } },
      { label: 'Scan Now',       click: () => server?.runScan() },
      { type: 'separator' },
      { label: 'Quit Sentinel',  click: () => { app.exit(0); } },
    ]));
  };

  rebuild();
  tray.on('click', () => { mainWindow?.show(); mainWindow?.focus(); });
  setInterval(rebuild, 10000);
}

// ── IPC Handlers ──────────────────────────────────────────────────────────────
ipcMain.handle('get-agent-id', () => server?.cfg?.agentId || os.hostname());
ipcMain.handle('open-external', (_, url) => shell.openExternal(url));

// ── App Lifecycle ─────────────────────────────────────────────────────────────
app.whenReady().then(() => {
  if (!isDev) startServer();
  createWindow();
  createTray();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
    else mainWindow?.show();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  if (server?.httpServer?.listening) server.httpServer.close();
});
