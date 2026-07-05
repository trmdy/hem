import type { HemEventMap, HemEventName, IpcArgs, IpcChannel, IpcResult } from '../shared/types';

export interface HemBridge {
  invoke<C extends IpcChannel>(channel: C, ...args: IpcArgs<C>): Promise<IpcResult<C>>;
  on<E extends HemEventName>(event: E, callback: (payload: HemEventMap[E]) => void): () => void;
}

declare global {
  interface Window {
    hem: HemBridge;
  }
}

export {};
