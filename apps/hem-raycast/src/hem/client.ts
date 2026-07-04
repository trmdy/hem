import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { classifyGrpcError, HemError } from "./errors";
import { ProtoScopeSelector, ProtoSecretRef } from "./refs";

// --- wire types (proto-loader: keepCase, string enums, defaults) ---

export type ApprovalState =
  | "APPROVAL_STATE_UNSPECIFIED"
  | "APPROVAL_STATE_PENDING"
  | "APPROVAL_STATE_APPROVED"
  | "APPROVAL_STATE_DENIED"
  | "APPROVAL_STATE_TIMED_OUT";

export type TokenType =
  "TOKEN_TYPE_UNSPECIFIED" | "TOKEN_TYPE_OPERATOR" | "TOKEN_TYPE_SERVICE" | "TOKEN_TYPE_AGENT_RUN";

export interface SecretInfo {
  scope: ProtoScopeSelector;
  name: string;
  description: string;
  requires_approval: boolean;
  group: string;
  created_at: string;
  updated_at: string;
  created_by: string;
  last_accessed_at: string;
  last_accessed_by: string;
}

export interface SecretWithValues {
  info: SecretInfo;
  values: Record<string, string>;
}

export interface PendingApproval {
  request_id: string;
  state: ApprovalState;
  message: string;
}

export interface GetSecretResponse {
  result?: "secret" | "pending";
  secret?: SecretWithValues;
  pending?: PendingApproval;
}

export interface DeleteSecretResponse {
  deleted: boolean;
  approval_request_id: string;
  approval_state: ApprovalState;
}

export interface ScanMatch {
  secret_ref: string;
  key: string;
  offset: number;
}

export interface ScanForSecretsResponse {
  clean: boolean;
  matches: ScanMatch[];
  scanned_length: number;
  secrets_checked: number;
}

export interface GroupInfo {
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface TokenInfo {
  token_id: string;
  token_type: TokenType;
  issued_at: string;
  expires_at: string;
  issued_by: string;
  service_name: string;
  identity_id: string;
  project: string;
  scopes: string[];
}

export interface GrantInfo {
  secret: ProtoSecretRef;
  grantee_scope: ProtoScopeSelector;
  grantee_id: string;
  created_at: string;
  created_by: string;
}

export interface ApprovalRequestInfo {
  request_id: string;
  state: ApprovalState;
  secret: ProtoSecretRef;
  requester_token_id: string;
  requester_identity_id: string;
  requester_project: string;
  reason: string;
  created_at: string;
  resolved_at: string;
  resolved_by: string;
  resolve_message: string;
  action: string;
  secret_version: string;
}

export interface ResolveApprovalResponse {
  request: ApprovalRequestInfo;
  approval_receipt: string;
}

export interface AuditEntry {
  audit_id: string;
  ts: string;
  action: string;
  actor: string;
  token_id: string;
  secret?: ProtoSecretRef;
  result: string;
  details: string;
}

export interface HealthResponse {
  status: string;
  version: string;
}

export interface InitHemResponse {
  initialized: boolean;
  operator_token: string;
}

// --- request shapes (only fields the extension uses; all optional-friendly) ---

export interface SecretLookup {
  secret?: ProtoSecretRef;
  name?: string;
  context?: { identity_id?: string; project?: string };
}

export interface SetSecretRequest {
  secret: ProtoSecretRef;
  values: Array<{ key: string; value: string }>;
  description?: string;
  requires_approval?: boolean;
  group?: string;
  actor?: string;
  approval_receipt?: string;
  reason?: string;
}

export interface ListSecretsRequest {
  scope?: ProtoScopeSelector;
  group?: string;
  prefix?: string;
  limit?: number;
}

export interface HemClientOptions {
  /** e.g. http://127.0.0.1:50091 — scheme is stripped for the gRPC target. */
  endpoint: string;
  token?: string | null;
  protoPath: string;
  timeoutMs?: number;
}

const NO_AUTH_METHODS = new Set(["Health", "InitHem"]);

/**
 * Typed wrapper over the full app-facing HemRuntime surface (vault, groups,
 * tokens, grants, approvals, audit, admin, health). Peer* RPCs are
 * deliberately not exposed — they use ed25519 transport auth and are not for
 * applications.
 */
export class HemClient {
  readonly endpoint: string;
  private readonly token: string | null;
  private readonly timeoutMs: number;
  private readonly grpcClient: InstanceType<grpc.ServiceClientConstructor>;

  constructor(opts: HemClientOptions) {
    this.endpoint = opts.endpoint;
    this.token = opts.token?.trim() || null;
    this.timeoutMs = opts.timeoutMs ?? 10_000;

    const definition = protoLoader.loadSync(opts.protoPath, {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true,
    });
    const pkg = grpc.loadPackageDefinition(definition) as unknown as {
      valhall: { hem: { v1: { HemRuntime: grpc.ServiceClientConstructor } } };
    };
    const target = opts.endpoint.replace(/^https?:\/\//, "").replace(/\/+$/, "");
    this.grpcClient = new pkg.valhall.hem.v1.HemRuntime(target, grpc.credentials.createInsecure());
  }

  close(): void {
    this.grpcClient.close();
  }

  private call<Res>(method: string, request: object): Promise<Res> {
    if (!this.token && !NO_AUTH_METHODS.has(method)) {
      return Promise.reject(new HemError(`${method}: no operator token available`, "unauthenticated", { method }));
    }
    const metadata = new grpc.Metadata();
    if (this.token && !NO_AUTH_METHODS.has(method)) {
      metadata.set("authorization", `Bearer ${this.token}`);
    }
    const deadline = new Date(Date.now() + this.timeoutMs);
    return new Promise<Res>((resolve, reject) => {
      type UnaryCall = (
        request: object,
        metadata: grpc.Metadata,
        options: { deadline: Date },
        callback: (err: unknown, response: Res) => void,
      ) => void;
      const fn = (this.grpcClient as unknown as Record<string, UnaryCall>)[method].bind(this.grpcClient);
      fn(request, metadata, { deadline }, (err, response) => {
        if (err) reject(classifyGrpcError(err, method));
        else resolve(response);
      });
    });
  }

  // Health / admin
  health(): Promise<HealthResponse> {
    return this.call("Health", {});
  }

  initHem(force = false): Promise<InitHemResponse> {
    return this.call("InitHem", { force });
  }

  // Vault
  setSecret(req: SetSecretRequest): Promise<SecretInfo> {
    return this.call("SetSecret", req);
  }

  getSecret(
    lookup: SecretLookup,
    opts: { key?: string; reason?: string; approvalReceipt?: string } = {},
  ): Promise<GetSecretResponse> {
    return this.call("GetSecret", {
      ...(lookup.secret ? { secret: lookup.secret } : { name: lookup.name }),
      ...(lookup.context ? { context: lookup.context } : {}),
      ...(opts.key ? { key: opts.key } : {}),
      ...(opts.reason ? { reason: opts.reason } : {}),
      ...(opts.approvalReceipt ? { approval_receipt: opts.approvalReceipt } : {}),
    });
  }

  getSecretInfo(lookup: SecretLookup): Promise<SecretInfo> {
    return this.call("GetSecretInfo", {
      ...(lookup.secret ? { secret: lookup.secret } : { name: lookup.name }),
      ...(lookup.context ? { context: lookup.context } : {}),
    });
  }

  deleteSecret(
    secret: ProtoSecretRef,
    opts: { actor?: string; approvalReceipt?: string; reason?: string } = {},
  ): Promise<DeleteSecretResponse> {
    return this.call("DeleteSecret", {
      secret,
      ...(opts.actor ? { actor: opts.actor } : {}),
      ...(opts.approvalReceipt ? { approval_receipt: opts.approvalReceipt } : {}),
      ...(opts.reason ? { reason: opts.reason } : {}),
    });
  }

  listSecrets(req: ListSecretsRequest = {}): Promise<SecretInfo[]> {
    return this.call<{ secrets: SecretInfo[] }>("ListSecrets", req).then((r) => r.secrets ?? []);
  }

  scanForSecrets(text: string, opts: { minValueLength?: number } = {}): Promise<ScanForSecretsResponse> {
    return this.call("ScanForSecrets", {
      text,
      ...(opts.minValueLength ? { min_value_length: opts.minValueLength } : {}),
    });
  }

  // Groups
  setGroup(name: string, description = ""): Promise<GroupInfo> {
    return this.call("SetGroup", { name, description });
  }

  addToGroup(secret: ProtoSecretRef, group: string): Promise<GroupInfo> {
    return this.call("AddToGroup", { secret, group });
  }

  removeFromGroup(secret: ProtoSecretRef): Promise<{ updated: boolean }> {
    return this.call("RemoveFromGroup", { secret });
  }

  listGroups(): Promise<GroupInfo[]> {
    return this.call<{ groups: GroupInfo[] }>("ListGroups", {}).then((r) => r.groups ?? []);
  }

  listGroupSecrets(group: string): Promise<SecretInfo[]> {
    return this.call<{ secrets: SecretInfo[] }>("ListGroupSecrets", { group }).then((r) => r.secrets ?? []);
  }

  // Tokens
  issueServiceToken(
    serviceName: string,
    ttlSeconds: number,
    issuedBy = "",
  ): Promise<{ token: string; info: TokenInfo }> {
    return this.call("IssueServiceToken", { service_name: serviceName, ttl_seconds: ttlSeconds, issued_by: issuedBy });
  }

  issueAgentToken(req: {
    identity_id?: string;
    project?: string;
    scopes?: string[];
    ttl_seconds?: number;
    issued_by_service?: string;
  }): Promise<{ token: string; info: TokenInfo }> {
    return this.call("IssueAgentToken", req);
  }

  revokeToken(tokenId: string, actor = ""): Promise<{ revoked: boolean }> {
    return this.call("RevokeToken", { token_id: tokenId, actor });
  }

  listActiveTokens(
    req: { token_type?: TokenType; service_name?: string; identity_id?: string; limit?: number } = {},
  ): Promise<TokenInfo[]> {
    return this.call<{ tokens: TokenInfo[] }>("ListActiveTokens", req).then((r) => r.tokens ?? []);
  }

  // Grants
  grantAccess(
    secret: ProtoSecretRef,
    granteeScope: ProtoScopeSelector,
    granteeId: string,
    actor = "",
  ): Promise<GrantInfo> {
    return this.call("GrantAccess", { secret, grantee_scope: granteeScope, grantee_id: granteeId, actor });
  }

  revokeAccess(
    secret: ProtoSecretRef,
    granteeScope: ProtoScopeSelector,
    granteeId: string,
    actor = "",
  ): Promise<{ revoked: boolean }> {
    return this.call("RevokeAccess", { secret, grantee_scope: granteeScope, grantee_id: granteeId, actor });
  }

  listGrants(secret: ProtoSecretRef): Promise<GrantInfo[]> {
    return this.call<{ grants: GrantInfo[] }>("ListGrants", { secret }).then((r) => r.grants ?? []);
  }

  // Approvals
  listPendingApprovals(limit = 100): Promise<ApprovalRequestInfo[]> {
    return this.call<{ requests: ApprovalRequestInfo[] }>("ListPendingApprovals", { limit }).then(
      (r) => r.requests ?? [],
    );
  }

  approveAccess(requestId: string, opts: { actor?: string; message?: string } = {}): Promise<ResolveApprovalResponse> {
    return this.call("ApproveAccess", { request_id: requestId, actor: opts.actor ?? "", message: opts.message ?? "" });
  }

  denyAccess(requestId: string, opts: { actor?: string; message?: string } = {}): Promise<ResolveApprovalResponse> {
    return this.call("DenyAccess", { request_id: requestId, actor: opts.actor ?? "", message: opts.message ?? "" });
  }

  getApprovalStatus(requestId: string): Promise<{ request: ApprovalRequestInfo }> {
    return this.call("GetApprovalStatus", { request_id: requestId });
  }

  // Audit
  getAuditLog(
    req: { scope?: ProtoScopeSelector; since?: string; until?: string; limit?: number } = {},
  ): Promise<AuditEntry[]> {
    return this.call<{ entries: AuditEntry[] }>("GetAuditLog", req).then((r) => r.entries ?? []);
  }

  // Admin (exposed for surface completeness; not wired to any UI on purpose)
  rotateMasterKey(actor = ""): Promise<{ new_key_id: string; rotated_secret_count: number }> {
    return this.call("RotateMasterKey", { actor });
  }

  exportSecrets(scope?: ProtoScopeSelector): Promise<{ encrypted_bundle: Buffer }> {
    return this.call("ExportSecrets", scope ? { scope } : {});
  }

  importSecrets(encryptedBundle: Buffer, merge = false, actor = ""): Promise<{ imported_secret_count: number }> {
    return this.call("ImportSecrets", { encrypted_bundle: encryptedBundle, merge, actor });
  }
}
