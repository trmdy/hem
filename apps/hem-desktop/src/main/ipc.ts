import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type {
  ApprovalRow,
  AuditRow,
  CollisionRow,
  DaemonHealth,
  GrantRow,
  IpcArgs,
  IpcChannel,
  IpcResult,
  MeshHealth,
  MeshSnapshot,
  ScopeKind,
  SecretDetail,
  SecretRow,
  TokenRow,
} from '../shared/types';
import type { ClipboardAdapter } from './clipboard';
import { ACTOR, HemDeskConfig } from './config';
import type {
  ApprovalRequestInfo,
  ApprovalState,
  HemClient,
  SecretInfo,
  TokenInfo,
} from './hem/client';
import {
  clusterHealthFromOutput,
  getClusterSnapshot,
  parseKvOutput,
  runCluster,
} from './hem/cluster';
import { HemError, isHemError } from './hem/errors';
import { getVersionHistory } from './hem/history';
import { formatRef, parseRef, protoToRef, refToProto, scopeSectionKey } from './hem/refs';
import { logError } from './log';
import { maskKeys } from './redact';

export interface HandlerContext {
  client: HemClient;
  config: HemDeskConfig;
  clipboard: ClipboardAdapter;
}

// --- mapping helpers ---

function rowFromInfo(info: SecretInfo): SecretRow {
  const parts = protoToRef(info.scope, info.name);
  return {
    ref: formatRef(parts),
    scope: parts.scope,
    section: scopeSectionKey(parts),
    name: info.name,
    description: info.description ?? '',
    group: info.group ?? '',
    requiresApproval: Boolean(info.requires_approval),
    createdAt: info.created_at ?? '',
    updatedAt: info.updated_at ?? '',
    createdBy: info.created_by ?? '',
  };
}

const APPROVAL_STATE: Record<ApprovalState, ApprovalRow['state']> = {
  APPROVAL_STATE_UNSPECIFIED: 'unknown',
  APPROVAL_STATE_PENDING: 'pending',
  APPROVAL_STATE_APPROVED: 'approved',
  APPROVAL_STATE_DENIED: 'denied',
  APPROVAL_STATE_TIMED_OUT: 'timed_out',
};

function approvalFromInfo(req: ApprovalRequestInfo): ApprovalRow {
  return {
    requestId: req.request_id,
    state: APPROVAL_STATE[req.state] ?? 'unknown',
    ref: req.secret ? formatRef(protoToRef(req.secret.scope, req.secret.name)) : '',
    action: req.action ?? '',
    requesterTokenId: req.requester_token_id ?? '',
    requesterIdentityId: req.requester_identity_id ?? '',
    requesterProject: req.requester_project ?? '',
    reason: req.reason ?? '',
    createdAt: req.created_at ?? '',
    resolvedAt: req.resolved_at ?? '',
    resolvedBy: req.resolved_by ?? '',
    resolveMessage: req.resolve_message ?? '',
  };
}

const TOKEN_TYPE: Record<string, TokenRow['tokenType']> = {
  TOKEN_TYPE_OPERATOR: 'operator',
  TOKEN_TYPE_SERVICE: 'service',
  TOKEN_TYPE_AGENT_RUN: 'agent-run',
};

function tokenFromInfo(info: TokenInfo): TokenRow {
  return {
    tokenId: info.token_id,
    tokenType: TOKEN_TYPE[info.token_type] ?? 'unknown',
    issuedAt: info.issued_at ?? '',
    expiresAt: info.expires_at ?? '',
    issuedBy: info.issued_by ?? '',
    serviceName: info.service_name ?? '',
    identityId: info.identity_id ?? '',
    project: info.project ?? '',
    scopes: info.scopes ?? [],
  };
}

function grantFromInfo(g: {
  secret: { scope: { scope: string; project?: string; identity_id?: string }; name: string };
  grantee_scope: { scope: string; project?: string; identity_id?: string };
  grantee_id: string;
  created_at: string;
  created_by: string;
}): GrantRow {
  const granteeParts = protoToRef(g.grantee_scope, '');
  return {
    ref: g.secret ? formatRef(protoToRef(g.secret.scope, g.secret.name)) : '',
    granteeScope: granteeParts.scope,
    granteeId: g.grantee_id ?? '',
    createdAt: g.created_at ?? '',
    createdBy: g.created_by ?? '',
  };
}

function mustParseRef(ref: string) {
  const parts = parseRef(ref);
  if (!parts) {
    throw new HemError(`invalid secret ref: ${ref}`, 'invalid-argument');
  }
  return parts;
}

function scopeSelector(scope: { kind: ScopeKind; project?: string; identityId?: string }): {
  scope: string;
  project?: string;
  identity_id?: string;
} {
  switch (scope.kind) {
    case 'global':
      return { scope: 'SECRET_SCOPE_GLOBAL' };
    case 'project':
      return { scope: 'SECRET_SCOPE_PROJECT', project: scope.project };
    case 'identity':
      return { scope: 'SECRET_SCOPE_IDENTITY', identity_id: scope.identityId };
  }
}

function defaultDataDir(): string {
  if (process.env.HEM_DATA_DIR) return process.env.HEM_DATA_DIR;
  const daemons = join(homedir(), '.valhall', 'system-daemons', 'data', 'hem');
  if (existsSync(daemons)) return daemons;
  return join(homedir(), '.valhall', 'hem');
}

// --- handler factory ---

export type Handlers = {
  [C in IpcChannel]: (...args: IpcArgs<C>) => Promise<IpcResult<C>>;
};

const HEALTH_CACHE_DEFAULT_MS = 5 * 60 * 1000;

export function createHandlers(ctx: HandlerContext): Handlers {
  const { client, config, clipboard } = ctx;

  // Staged mesh loading (tech doc §2.1): `cluster health` runs ~30 s on this
  // cluster, so cache the last probe and let callers accept staleness up to
  // maxAgeMs (default 5 min — the hem-raycast launch-bug lesson). A single
  // in-flight probe is shared between concurrent callers.
  let healthCache: MeshHealth | null = null;
  let healthInFlight: Promise<MeshHealth> | null = null;
  let dataDirCache: string | null = null;

  async function probeHealth(): Promise<MeshHealth> {
    const res = await runCluster(config.hemBinary, ['health']);
    const parsed = clusterHealthFromOutput(res.stdout, res.exitCode);
    const s = parsed.scalars;
    const localNodeId = s.node_id ?? '';
    const health: MeshHealth = {
      status: parsed.status,
      peers: parsed.peers.map((p) => ({
        nodeId: p.nodeId,
        status: p.status,
        endpoint: p.endpoint,
        cursorPosition: p.cursorPosition,
        lag: p.lag,
        lastSeen: p.lastSeen,
        error: p.error,
        local: p.nodeId === localNodeId,
      })),
      latestPosition: Number.parseInt(s.latest_position ?? '', 10) || 0,
      latestBodyHash: s.latest_body_hash ?? '',
      collisions: Number.parseInt(s.collisions ?? '', 10) || 0,
      healthyPeers: Number.parseInt(s.healthy_peers ?? '', 10) || 0,
      laggingPeers: Number.parseInt(s.lagging_peers ?? '', 10) || 0,
      offlinePeers: Number.parseInt(s.offline_peers ?? '', 10) || 0,
      divergentPeers: Number.parseInt(s.divergent_peers ?? '', 10) || 0,
      quorumRisk: s.quorum_risk ?? '',
      checkpointStatus: s.checkpoint_status ?? '',
      checkpointCosignatures: Number.parseInt(s.latest_checkpoint_cosignatures ?? '', 10) || 0,
      syncErrors: s.sync_errors ?? '',
      scalars: s,
      probedAt: Date.now(),
      raw: parsed.raw,
    };
    healthCache = health;
    return health;
  }

  async function getDataDir(): Promise<string> {
    if (dataDirCache) return dataDirCache;
    try {
      const res = await runCluster(config.hemBinary, ['status']);
      dataDirCache = res.parsed.scalars.data_dir || defaultDataDir();
    } catch {
      dataDirCache = defaultDataDir();
    }
    return dataDirCache;
  }

  async function fetchValues(ref: string): Promise<Record<string, string>> {
    const parts = mustParseRef(ref);
    const res = await client.getSecret({ secret: refToProto(parts) }, { asyncRead: true });
    if (res.pending) {
      throw new HemError(
        `read of ${ref} is approval-gated (request ${res.pending.request_id})`,
        'failed-precondition',
      );
    }
    return res.secret?.values ?? {};
  }

  return {
    'app:config': async () => ({
      endpoint: config.endpoint,
      hemBinary: config.hemBinary,
      clipboardClearSeconds: config.clipboardClearSeconds,
      revealRemaskSeconds: config.revealRemaskSeconds,
      tokenSource: config.tokenDiscovery.source,
      hasToken: Boolean(config.tokenDiscovery.token),
    }),

    'daemon:health': async (): Promise<DaemonHealth> => {
      const res = await client.health();
      const fields: Record<string, string> = {};
      for (const token of (res.status ?? '').split(/\s+/)) {
        const eq = token.indexOf('=');
        if (eq > 0) fields[token.slice(0, eq)] = token.slice(eq + 1);
      }
      return {
        ok: (res.status ?? '').startsWith('ok'),
        status: res.status ?? '',
        version: res.version ?? '',
        fields,
        endpoint: config.endpoint,
        tokenSource: config.tokenDiscovery.source,
      };
    },

    'vault:list': async () => {
      const secrets = await client.listSecrets();
      return secrets.map(rowFromInfo);
    },

    'vault:get': async (ref): Promise<SecretDetail> => {
      const parts = mustParseRef(ref);
      const proto = refToProto(parts);
      const info = await client.getSecretInfo({ secret: proto });
      const row = rowFromInfo(info);

      let grants: GrantRow[] = [];
      try {
        grants = (await client.listGrants(proto)).map(grantFromInfo);
      } catch {
        // grants are operator-only; a service token still gets the detail view
      }

      try {
        const res = await client.getSecret({ secret: proto }, { asyncRead: true });
        if (res.pending) {
          return {
            row,
            keys: [],
            lastAccessedAt: info.last_accessed_at ?? '',
            lastAccessedBy: info.last_accessed_by ?? '',
            grants,
            pending: {
              requestId: res.pending.request_id,
              message: res.pending.message ?? '',
            },
          };
        }
        return {
          row,
          keys: maskKeys(res.secret?.values ?? {}),
          lastAccessedAt: info.last_accessed_at ?? '',
          lastAccessedBy: info.last_accessed_by ?? '',
          grants,
        };
      } catch (err) {
        // Cluster read-policy failures (peer_quorum / master unreachable):
        // explain, never retry-loop (reference 0004 §Semantics).
        if (isHemError(err) && err.kind === 'failed-precondition') {
          return {
            row,
            keys: [],
            lastAccessedAt: info.last_accessed_at ?? '',
            lastAccessedBy: info.last_accessed_by ?? '',
            grants,
            policyError: err.message,
          };
        }
        throw err;
      }
    },

    'vault:reveal': async (ref, key) => {
      const values = await fetchValues(ref);
      const value = values[key];
      if (value === undefined) {
        throw new HemError(`${ref} has no key "${key}"`, 'not-found');
      }
      return { value, remaskAfter: config.revealRemaskSeconds };
    },

    // The hot path: the value never crosses IPC — fetched, copied concealed,
    // and clear-scheduled entirely in the main process (tech doc §2.3).
    'vault:copy': async (ref, key) => {
      const values = await fetchValues(ref);
      const value = values[key];
      if (value === undefined) {
        throw new HemError(`${ref} has no key "${key}"`, 'not-found');
      }
      await clipboard.copyConcealed(value);
      clipboard.scheduleClear(value, config.clipboardClearSeconds);
      return { clearedAfter: config.clipboardClearSeconds };
    },

    'vault:set': async (input) => {
      const parts = mustParseRef(input.ref);
      await client.setSecret({
        secret: refToProto(parts),
        values: input.values,
        description: input.description,
        requires_approval: input.requiresApproval,
        group: input.group,
        actor: ACTOR,
        reason: input.reason,
        approval_receipt: input.approvalReceipt,
      });
      return { ok: true, ref: input.ref };
    },

    'vault:delete': async (ref, opts) => {
      const parts = mustParseRef(ref);
      const res = await client.deleteSecret(refToProto(parts), {
        actor: ACTOR,
        reason: opts?.reason,
        approvalReceipt: opts?.approvalReceipt,
      });
      if (res.deleted) return { deleted: true };
      return {
        deleted: false,
        approvalRequired: {
          requestId: res.approval_request_id,
          state: APPROVAL_STATE[res.approval_state] ?? 'unknown',
        },
      };
    },

    'clipboard:copyText': async (text, opts) => {
      if (opts?.concealed) {
        await clipboard.copyConcealed(text);
        clipboard.scheduleClear(text, config.clipboardClearSeconds);
      } else {
        await clipboard.copyPlain(text);
      }
    },

    'groups:list': async () => {
      const groups = await client.listGroups();
      return groups.map((g) => ({ name: g.name, description: g.description ?? '' }));
    },

    'approvals:list': async () => {
      const requests = await client.listPendingApprovals();
      return requests.map(approvalFromInfo);
    },

    'approvals:approve': async (requestId, message) => {
      const res = await client.approveAccess(requestId, { actor: ACTOR, message });
      return { request: approvalFromInfo(res.request), receipt: res.approval_receipt ?? '' };
    },

    'approvals:deny': async (requestId, message) => {
      const res = await client.denyAccess(requestId, { actor: ACTOR, message });
      return { request: approvalFromInfo(res.request) };
    },

    'tokens:list': async () => {
      const tokens = await client.listActiveTokens();
      return tokens.map(tokenFromInfo);
    },

    'tokens:issueService': async (serviceName, ttlSeconds) => {
      const res = await client.issueServiceToken(serviceName, ttlSeconds, ACTOR);
      return { token: res.token, info: tokenFromInfo(res.info) };
    },

    'tokens:issueAgent': async (req) => {
      const res = await client.issueAgentToken({
        identity_id: req.identityId,
        project: req.project,
        scopes: req.scopes,
        ttl_seconds: req.ttlSeconds,
      });
      return { token: res.token, info: tokenFromInfo(res.info) };
    },

    'tokens:revoke': async (tokenId) => {
      return client.revokeToken(tokenId, ACTOR);
    },

    'grants:list': async (ref) => {
      const parts = mustParseRef(ref);
      const grants = await client.listGrants(refToProto(parts));
      return grants.map(grantFromInfo);
    },

    'grants:grant': async (ref, grantee) => {
      const parts = mustParseRef(ref);
      const grant = await client.grantAccess(
        refToProto(parts),
        scopeSelector(grantee),
        grantee.id,
        ACTOR,
      );
      return grantFromInfo(grant);
    },

    'grants:revoke': async (ref, grantee) => {
      const parts = mustParseRef(ref);
      return client.revokeAccess(refToProto(parts), scopeSelector(grantee), grantee.id, ACTOR);
    },

    'audit:query': async (query): Promise<AuditRow[]> => {
      const entries = await client.getAuditLog({
        limit: query.limit ?? 100,
        until: query.until,
        scope: query.scope ? scopeSelector(query.scope) : undefined,
      });
      return entries.map((e) => ({
        auditId: e.audit_id,
        ts: e.ts,
        action: e.action ?? '',
        actor: e.actor ?? '',
        tokenId: e.token_id ?? '',
        ref: e.secret ? formatRef(protoToRef(e.secret.scope, e.secret.name)) : null,
        result: e.result ?? '',
        details: e.details ?? '',
      }));
    },

    'mesh:snapshot': async (): Promise<MeshSnapshot> => {
      const snap = await getClusterSnapshot(config.hemBinary);
      const s = snap.scalars;
      if (s.data_dir) dataDirCache = s.data_dir;
      return {
        clusterId: s.cluster_id ?? '',
        nodeId: s.node_id ?? '',
        quorum: Number.parseInt(s.quorum ?? '', 10) || 0,
        masterNodeId: s.master_node_id ?? '',
        checkpoints: Number.parseInt(s.checkpoints ?? '', 10) || 0,
        latestCheckpointPosition: Number.parseInt(s.latest_checkpoint_position ?? '', 10) || 0,
        latestCheckpointCosignatures:
          Number.parseInt(s.latest_checkpoint_cosignatures ?? '', 10) || 0,
        peers: snap.peers.map((p) => ({ nodeId: p.nodeId, endpoint: p.endpoint })),
        scalars: s,
      };
    },

    'mesh:health': async (opts): Promise<MeshHealth> => {
      const maxAgeMs = opts?.maxAgeMs ?? HEALTH_CACHE_DEFAULT_MS;
      if (healthCache && Date.now() - healthCache.probedAt <= maxAgeMs) {
        return healthCache;
      }
      if (!healthInFlight) {
        healthInFlight = probeHealth().finally(() => {
          healthInFlight = null;
        });
      }
      return healthInFlight;
    },

    'mesh:collisions': async (): Promise<CollisionRow[]> => {
      const res = await runCluster(config.hemBinary, ['collisions']);
      return res.parsed.records
        .filter((r) => r.type === 'collision')
        .map((r) => {
          const id = r.fields.collision_id ?? r.fields.id ?? '';
          return {
            fields: r.fields,
            resolveCommand: id
              ? `hem cluster resolve-collision ${id} --keep <local|remote>`
              : 'hem cluster collisions',
          };
        });
    },

    'mesh:syncOnce': async () => {
      const res = await runCluster(config.hemBinary, ['sync', '--once']);
      const parsed = parseKvOutput(res.stdout);
      const summary =
        Object.entries(parsed.scalars)
          .map(([k, v]) => `${k}=${v}`)
          .join(' · ') ||
        res.stdout.trim().slice(0, 200) ||
        (res.exitCode === 0 ? 'sync complete' : `sync exited ${res.exitCode}`);
      return { exitCode: res.exitCode, summary };
    },

    'scan:text': async (text) => {
      const res = await client.scanForSecrets(text);
      return {
        clean: Boolean(res.clean),
        matches: (res.matches ?? []).map((m) => ({
          ref: m.secret_ref,
          key: m.key,
          offset: Number(m.offset) || 0,
        })),
        scannedLength: Number(res.scanned_length) || 0,
        secretsChecked: Number(res.secrets_checked) || 0,
      };
    },

    'history:versions': async (ref) => {
      try {
        return await getVersionHistory(await getDataDir(), ref);
      } catch (err) {
        logError('history:versions failed', err);
        return [];
      }
    },
  };
}

/**
 * Serialize errors crossing IPC as "[kind] message" so the renderer can
 * classify without a structured channel (Electron flattens thrown errors
 * to their message string).
 */
export function toIpcError(err: unknown): Error {
  if (isHemError(err)) {
    return new Error(`[${err.kind}] ${err.message}`);
  }
  const message = err instanceof Error ? err.message : String(err);
  return new Error(`[unknown] ${message}`);
}
