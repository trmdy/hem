import type { HemEventMap, HemEventName } from '../../shared/types';
import { logInfo } from '../log';

export type EventForwarder = <E extends HemEventName>(event: E, payload: HemEventMap[E]) => void;

const NATS_URL = '127.0.0.1:4222';

/**
 * Live updates over NATS (`hem.*`). Strictly an enhancement: if the server
 * is down we report disconnected and the renderer falls back to polling.
 * Payloads are ignored on purpose — subjects alone say what to refetch, so
 * no event body (which could name secrets) is retained or logged.
 */
export function startNatsBridge(forward: EventForwarder): { stop: () => Promise<void> } {
  let stopped = false;
  let closer: (() => Promise<void>) | null = null;

  (async () => {
    let nats: typeof import('nats');
    try {
      nats = await import('nats');
    } catch {
      forward('hem:nats-status', { connected: false });
      return;
    }
    while (!stopped) {
      try {
        const conn = await nats.connect({
          servers: NATS_URL,
          reconnect: true,
          maxReconnectAttempts: -1,
          waitOnFirstConnect: false,
        });
        closer = () => conn.close();
        forward('hem:nats-status', { connected: true });
        logInfo('nats connected');

        (async () => {
          for await (const status of conn.status()) {
            if (status.type === 'disconnect') forward('hem:nats-status', { connected: false });
            if (status.type === 'reconnect') forward('hem:nats-status', { connected: true });
          }
        })().catch(() => {});

        const sub = conn.subscribe('hem.>');
        for await (const msg of sub) {
          const subject = msg.subject;
          if (subject.startsWith('hem.approval.')) {
            forward('hem:approval', {
              kind: subject.endsWith('.requested') ? 'requested' : 'resolved',
            });
          } else if (subject === 'hem.secret.read') {
            forward('hem:audit-changed', {});
          } else if (subject.startsWith('hem.secret.')) {
            forward('hem:secret-changed', {});
          } else if (subject.startsWith('hem.token.')) {
            forward('hem:token-changed', {});
          }
        }
        if (stopped) return;
      } catch {
        forward('hem:nats-status', { connected: false });
      }
      if (!stopped) {
        await new Promise((resolve) => setTimeout(resolve, 15_000));
      }
    }
  })().catch(() => {
    forward('hem:nats-status', { connected: false });
  });

  return {
    stop: async () => {
      stopped = true;
      if (closer) await closer().catch(() => {});
    },
  };
}
