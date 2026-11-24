import { contextBridge, ipcRenderer } from 'electron';

/**
 * The renderer gets exactly two capabilities: invoke a known hem channel,
 * and subscribe to a known hem event. Channel allowlists live here so a
 * compromised renderer can't reach arbitrary IPC.
 */

const INVOKE_CHANNELS = new Set([
  'app:config',
  'daemon:health',
  'vault:list',
  'vault:get',
  'vault:reveal',
  'vault:copy',
  'vault:set',
  'vault:delete',
  'clipboard:copyText',
  'groups:list',
  'approvals:list',
  'approvals:approve',
  'approvals:deny',
  'tokens:list',
  'tokens:issueService',
  'tokens:issueAgent',
  'tokens:revoke',
  'grants:list',
  'grants:grant',
  'grants:revoke',
  'audit:query',
  'mesh:snapshot',
  'mesh:health',
  'mesh:collisions',
  'mesh:syncOnce',
  'scan:text',
  'history:versions',
]);

const EVENT_CHANNELS = new Set([
  'hem:approval',
  'hem:audit-changed',
  'hem:secret-changed',
  'hem:token-changed',
  'hem:nats-status',
]);

contextBridge.exposeInMainWorld('hem', {
  invoke: (channel: string, ...args: unknown[]): Promise<unknown> => {
    if (!INVOKE_CHANNELS.has(channel)) {
      return Promise.reject(new Error(`unknown IPC channel: ${channel}`));
    }
    return ipcRenderer.invoke(channel, ...args);
  },
  on: (event: string, callback: (payload: unknown) => void): (() => void) => {
    if (!EVENT_CHANNELS.has(event)) {
      throw new Error(`unknown event: ${event}`);
    }
    const listener = (_e: unknown, payload: unknown): void => callback(payload);
    ipcRenderer.on(event, listener);
    return () => ipcRenderer.removeListener(event, listener);
  },
});
