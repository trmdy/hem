import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import type { AuditQuery, IpcArgs, IpcChannel, IpcResult } from '../../shared/types';

export function invoke<C extends IpcChannel>(channel: C, ...args: IpcArgs<C>): Promise<IpcResult<C>> {
  return window.hem.invoke(channel, ...args);
}

/** Parse the "[kind] message" error convention from main. */
export function errorKind(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  const match = message.match(/\[([a-z-]+)\]/);
  return match ? match[1] : 'unknown';
}

export function errorText(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  // strip Electron's "Error invoking remote method 'x': Error: [kind]" wrapper
  const idx = message.lastIndexOf(']');
  return idx >= 0 ? message.slice(idx + 1).trim() : message;
}

export function isDaemonUnreachable(err: unknown): boolean {
  return errorKind(err) === 'unreachable' || errorKind(err) === 'timeout';
}

// --- queries ---

export function useDaemonHealth() {
  return useQuery({
    queryKey: ['daemon:health'],
    queryFn: () => invoke('daemon:health'),
    refetchInterval: 15_000,
    retry: false,
  });
}

export function useAppConfig() {
  return useQuery({ queryKey: ['app:config'], queryFn: () => invoke('app:config'), staleTime: Infinity });
}

export function useVaultList() {
  return useQuery({
    queryKey: ['vault:list'],
    queryFn: () => invoke('vault:list'),
    refetchInterval: 60_000,
    retry: false,
  });
}

export function useSecretDetail(ref: string | null) {
  return useQuery({
    queryKey: ['vault:get', ref],
    queryFn: () => invoke('vault:get', ref as string),
    enabled: ref !== null,
    retry: false,
  });
}

export function useGroups() {
  return useQuery({ queryKey: ['groups:list'], queryFn: () => invoke('groups:list'), retry: false });
}

export function useApprovals() {
  return useQuery({
    queryKey: ['approvals:list'],
    queryFn: () => invoke('approvals:list'),
    refetchInterval: 30_000,
    retry: false,
  });
}

export function useTokens() {
  return useQuery({
    queryKey: ['tokens:list'],
    queryFn: () => invoke('tokens:list'),
    refetchInterval: 60_000,
    retry: false,
  });
}

export function useAudit(query: AuditQuery) {
  return useQuery({
    queryKey: ['audit:query', query],
    queryFn: () => invoke('audit:query', query),
    retry: false,
  });
}

export function useMeshSnapshot() {
  return useQuery({
    queryKey: ['mesh:snapshot'],
    queryFn: () => invoke('mesh:snapshot'),
    refetchInterval: 60_000,
    retry: false,
  });
}

/**
 * The slow (~30 s) probe. Staleness policy lives in main (5-min cache);
 * this query simply asks and renders whatever arrives — the UI paints the
 * snapshot first and lets this stream in (hem-raycast launch-bug lesson).
 */
export function useMeshHealth() {
  return useQuery({
    queryKey: ['mesh:health'],
    queryFn: () => invoke('mesh:health', {}),
    refetchInterval: 5 * 60 * 1000,
    retry: false,
    staleTime: 4 * 60 * 1000,
  });
}

export function useCollisions(enabled: boolean) {
  return useQuery({
    queryKey: ['mesh:collisions'],
    queryFn: () => invoke('mesh:collisions'),
    enabled,
    retry: false,
  });
}

export function useVersionHistory(ref: string | null) {
  return useQuery({
    queryKey: ['history:versions', ref],
    queryFn: () => invoke('history:versions', ref as string),
    enabled: ref !== null,
    retry: false,
    staleTime: 60_000,
  });
}

/** Subscribe to main-process events and invalidate the affected queries. */
export function useHemEvents() {
  const queryClient = useQueryClient();
  useEffect(() => {
    const offs = [
      window.hem.on('hem:approval', () => {
        void queryClient.invalidateQueries({ queryKey: ['approvals:list'] });
        void queryClient.invalidateQueries({ queryKey: ['audit:query'] });
      }),
      window.hem.on('hem:audit-changed', () => {
        void queryClient.invalidateQueries({ queryKey: ['audit:query'] });
      }),
      window.hem.on('hem:secret-changed', () => {
        void queryClient.invalidateQueries({ queryKey: ['vault:list'] });
        void queryClient.invalidateQueries({ queryKey: ['vault:get'] });
        void queryClient.invalidateQueries({ queryKey: ['audit:query'] });
      }),
      window.hem.on('hem:token-changed', () => {
        void queryClient.invalidateQueries({ queryKey: ['tokens:list'] });
      }),
    ];
    return () => offs.forEach((off) => off());
  }, [queryClient]);
}
