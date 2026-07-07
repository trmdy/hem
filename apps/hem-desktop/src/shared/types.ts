/**
 * Shared IPC contract between main and renderer.
 *
 * Rule of the house (tech doc §2.3): no secret value ever crosses this
 * boundary except the explicit one-shot `vault:reveal` result. `vault:copy`
 * keeps the value entirely in the main process.
 */

export type ScopeKind = 'global' | 'project' | 'identity';

export interface SecretRow {
  /** Full explicit ref: global/<n>, project/<p>/<n>, identity/<i>/<n>. */
  ref: string;
  scope: ScopeKind;
  /** Section key for list grouping: "global", "project/<p>", "identity/<i>". */
  section: string;
  name: string;
  description: string;
  group: string;
  requiresApproval: boolean;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

export interface MaskedKey {
  key: string;
  /** e.g. "••••••••••••7f2a" — computed in main; the value never leaves it. */
  masked: string;
  length: number;
}

export interface GrantRow {
  ref: string;
  granteeScope: ScopeKind;
  granteeId: string;
  createdAt: string;
  createdBy: string;
}

export interface VersionRow {
  versionSeq: number;
  node: string;
  createdAt: string;
  /** Operation kind if derivable from ledger metadata ("set", "delete"). */
  kind: string;
}

export interface SecretDetail {
  row: SecretRow;
  keys: MaskedKey[];
  lastAccessedAt: string;
  lastAccessedBy: string;
  grants: GrantRow[];
  /** Approval-gated read pending (non-operator tokens). */
  pending?: { requestId: string; message: string };
  /** Read blocked by cluster read policy — explain, don't retry. */
  policyError?: string;
}

export interface SetSecretInput {
  ref: string;
  values: Array<{ key: string; value: string }>;
  description?: string;
  requiresApproval?: boolean;
  group?: string;
  reason?: string;
  approvalReceipt?: string;
}

export interface SetSecretResult {
  ok: boolean;
  ref: string;
  approvalRequired?: { requestId: string };
}

export interface DeleteResult {
  deleted: boolean;
  approvalRequired?: { requestId: string; state: string };
}

export interface ApprovalRow {
  requestId: string;
  state: 'pending' | 'approved' | 'denied' | 'timed_out' | 'unknown';
  ref: string;
  action: string;
  requesterTokenId: string;
  requesterIdentityId: string;
  requesterProject: string;
  reason: string;
  createdAt: string;
  resolvedAt: string;
  resolvedBy: string;
  resolveMessage: string;
}

export interface ApproveResult {
  request: ApprovalRow;
  /** Single-use, action-bound receipt. Shown once; hem does not store it. */
  receipt: string;
}

export interface TokenRow {
  tokenId: string;
  tokenType: 'operator' | 'service' | 'agent-run' | 'unknown';
  issuedAt: string;
  expiresAt: string;
  issuedBy: string;
  serviceName: string;
  identityId: string;
  project: string;
  scopes: string[];
}

export interface IssueTokenResult {
  /** The bearer token. Shown once, copy-only; never persisted by the app. */
  token: string;
  info: TokenRow;
}

export interface AuditRow {
  auditId: string;
  ts: string;
  action: string;
  actor: string;
  tokenId: string;
  ref: string | null;
  result: string;
  details: string;
}

export interface AuditQuery {
  limit?: number;
  /** Return entries strictly older than this RFC3339 timestamp (pagination). */
  until?: string;
  scope?: { kind: ScopeKind; project?: string; identityId?: string };
}

export interface GroupRow {
  name: string;
  description: string;
}

export interface DaemonHealth {
  ok: boolean;
  /** Raw status line, e.g. "ok cluster_enabled=true node_id=…". */
  status: string;
  version: string;
  /** Parsed from the status line when present. */
  fields: Record<string, string>;
  endpoint: string;
  tokenSource: string | null;
}

export interface MeshPeerConfig {
  nodeId: string;
  endpoint: string;
}

export interface MeshSnapshot {
  clusterId: string;
  nodeId: string;
  quorum: number;
  masterNodeId: string;
  checkpoints: number;
  latestCheckpointPosition: number;
  latestCheckpointCosignatures: number;
  peers: MeshPeerConfig[];
  scalars: Record<string, string>;
}

export interface MeshPeerHealth {
  nodeId: string;
  status: 'caught_up' | 'lagging' | 'offline' | 'divergent' | 'unknown';
  endpoint: string;
  cursorPosition: number;
  lag: number;
  lastSeen: string | null;
  error: string | null;
  local: boolean;
}

export interface MeshHealth {
  status: 'ok' | 'warning' | 'critical' | 'unknown';
  peers: MeshPeerHealth[];
  latestPosition: number;
  latestBodyHash: string;
  collisions: number;
  healthyPeers: number;
  laggingPeers: number;
  offlinePeers: number;
  divergentPeers: number;
  quorumRisk: string;
  checkpointStatus: string;
  checkpointCosignatures: number;
  syncErrors: string;
  scalars: Record<string, string>;
  /** Epoch ms when this probe finished (main-process cache stamp). */
  probedAt: number;
  raw: string;
}

export interface CollisionRow {
  fields: Record<string, string>;
  /** Ready-made `hem cluster resolve-collision …` command (runbook stance). */
  resolveCommand: string;
}

export interface SyncResult {
  exitCode: number;
  summary: string;
}

export interface ScanMatchRow {
  ref: string;
  key: string;
  offset: number;
}

export interface ScanResult {
  clean: boolean;
  matches: ScanMatchRow[];
  scannedLength: number;
  secretsChecked: number;
}

export interface AppConfigInfo {
  endpoint: string;
  hemBinary: string;
  clipboardClearSeconds: number;
  revealRemaskSeconds: number;
  tokenSource: string | null;
  hasToken: boolean;
}

/** Typed request map: channel → [args, result]. */
export interface IpcContract {
  'app:config': [[], AppConfigInfo];
  'daemon:health': [[], DaemonHealth];
  'vault:list': [[], SecretRow[]];
  'vault:get': [[ref: string], SecretDetail];
  'vault:reveal': [[ref: string, key: string], { value: string; remaskAfter: number }];
  'vault:copy': [[ref: string, key: string], { clearedAfter: number }];
  'vault:set': [[input: SetSecretInput], SetSecretResult];
  'vault:delete': [
    [ref: string, opts?: { reason?: string; approvalReceipt?: string }],
    DeleteResult,
  ];
  'clipboard:copyText': [[text: string, opts?: { concealed?: boolean }], void];
  'groups:list': [[], GroupRow[]];
  'approvals:list': [[], ApprovalRow[]];
  'approvals:approve': [[requestId: string, message?: string], ApproveResult];
  'approvals:deny': [[requestId: string, message?: string], { request: ApprovalRow }];
  'tokens:list': [[], TokenRow[]];
  'tokens:issueService': [[serviceName: string, ttlSeconds: number], IssueTokenResult];
  'tokens:issueAgent': [
    [req: { identityId?: string; project?: string; scopes?: string[]; ttlSeconds: number }],
    IssueTokenResult,
  ];
  'tokens:revoke': [[tokenId: string], { revoked: boolean }];
  'grants:list': [[ref: string], GrantRow[]];
  'grants:grant': [
    [ref: string, grantee: { kind: ScopeKind; project?: string; identityId?: string; id: string }],
    GrantRow,
  ];
  'grants:revoke': [
    [ref: string, grantee: { kind: ScopeKind; project?: string; identityId?: string; id: string }],
    { revoked: boolean },
  ];
  'audit:query': [[query: AuditQuery], AuditRow[]];
  'mesh:snapshot': [[], MeshSnapshot];
  'mesh:health': [[opts?: { maxAgeMs?: number }], MeshHealth];
  'mesh:collisions': [[], CollisionRow[]];
  'mesh:syncOnce': [[], SyncResult];
  'scan:text': [[text: string], ScanResult];
  'history:versions': [[ref: string], VersionRow[]];
}

export type IpcChannel = keyof IpcContract;
export type IpcArgs<C extends IpcChannel> = IpcContract[C][0];
export type IpcResult<C extends IpcChannel> = IpcContract[C][1];

/** Events pushed main → renderer. */
export interface HemEventMap {
  'hem:approval': { kind: 'requested' | 'resolved'; requestId?: string };
  'hem:audit-changed': Record<string, never>;
  'hem:secret-changed': { ref?: string };
  'hem:token-changed': Record<string, never>;
  'hem:nats-status': { connected: boolean };
}

export type HemEventName = keyof HemEventMap;

/** Serialized error shape crossing IPC (HemError flattened). */
export interface IpcErrorShape {
  message: string;
  kind: string;
}
