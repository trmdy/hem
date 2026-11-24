import { app, BrowserWindow, clipboard as electronClipboard, ipcMain, shell } from 'electron';
import { join } from 'node:path';
import type { HemEventMap, HemEventName } from '../shared/types';
import { createDarwinClipboard } from './clipboard';
import { loadConfig } from './config';
import { HemClient } from './hem/client';
import { startNatsBridge } from './hem/events';
import { createHandlers, toIpcError } from './ipc';
import { logError, logInfo } from './log';

const config = loadConfig(app.getAppPath());

const client = new HemClient({
  endpoint: config.endpoint,
  token: config.tokenDiscovery.token,
  protoPath: config.protoPath,
});

const handlers = createHandlers({
  client,
  config,
  clipboard: createDarwinClipboard(electronClipboard),
});

for (const [channel, handler] of Object.entries(handlers)) {
  ipcMain.handle(channel, async (_event, ...args) => {
    try {
      return await (handler as (...a: unknown[]) => Promise<unknown>)(...args);
    } catch (err) {
      logError(channel, 'failed:', err);
      throw toIpcError(err);
    }
  });
}

let mainWindow: BrowserWindow | null = null;

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 980,
    minHeight: 600,
    show: false,
    // Design 1a: traffic lights inline with the 44px title bar.
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 16, y: 16 },
    backgroundColor: '#ffffff',
    webPreferences: {
      preload: join(import.meta.dirname, '../preload/index.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
    },
  });

  // No remote content, ever (tech doc §3).
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://')) void shell.openExternal(url);
    return { action: 'deny' };
  });
  mainWindow.webContents.on('will-navigate', (event) => event.preventDefault());

  mainWindow.on('ready-to-show', () => mainWindow?.show());
  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  if (process.env.ELECTRON_RENDERER_URL) {
    void mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL);
  } else {
    void mainWindow.loadFile(join(import.meta.dirname, '../renderer/index.html'));
  }
}

function forward<E extends HemEventName>(event: E, payload: HemEventMap[E]): void {
  mainWindow?.webContents.send(event, payload);
}

const nats = startNatsBridge(forward);

app.whenReady().then(() => {
  logInfo('hem-desk starting', {
    endpoint: config.endpoint,
    tokenSource: config.tokenDiscovery.source ?? 'none',
  });
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  app.quit();
});

app.on('before-quit', () => {
  void nats.stop();
  client.close();
});
