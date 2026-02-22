import * as grpc from "@grpc/grpc-js";
export declare const sdkName = "@valhall/hem-sdk";
export type SecretScopeKind = "global" | "project" | "identity";
export type ApprovalState = "pending" | "approved" | "denied" | "timed_out" | "unspecified";
export interface HemClientOptions {
    endpoint?: string;
    token?: string;
    timeoutMs?: number;
    protoPath?: string;
    credentials?: grpc.ChannelCredentials;
}
export interface HemScopeSelector {
    scope: SecretScopeKind;
    project?: string;
    identityId?: string;
}
export interface HemSecretRef {
    scope: HemScopeSelector;
    name: string;
}
export interface HemScopeContext {
    identityId?: string;
    project?: string;
}
export interface HemSetOptions {
    description?: string;
    requiresApproval?: boolean;
    group?: string;
    actor?: string;
    approvalReceipt?: string;
    reason?: string;
}
export interface HemGetOptions extends HemScopeContext {
    key?: string;
    asyncRead?: boolean;
    waitTimeoutMs?: number;
    reason?: string;
    approvalReceipt?: string;
}
export interface HemGetBatchRequest extends HemGetOptions {
    secret: string;
}
export interface HemDeleteOptions {
    actor?: string;
    approvalReceipt?: string;
    reason?: string;
}
export interface HemWaitForApprovalOptions {
    timeoutMs?: number;
    pollIntervalMs?: number;
}
export interface HemSecretInfo {
    scope: HemScopeSelector;
    name: string;
    description?: string;
    requiresApproval: boolean;
    group?: string;
    createdAt?: string;
    updatedAt?: string;
    createdBy?: string;
    lastAccessedAt?: string;
    lastAccessedBy?: string;
}
export interface HemSecretWithValues {
    info: HemSecretInfo;
    values: Record<string, string>;
}
export interface HemPendingApproval {
    requestId: string;
    state: ApprovalState;
    message?: string;
}
export interface HemGetSecretResult {
    kind: "secret";
    secret: HemSecretWithValues;
    value?: string;
}
export interface HemGetPendingResult {
    kind: "pending";
    pending: HemPendingApproval;
}
export interface HemBatchErrorResult {
    kind: "error";
    error: string;
}
export type HemGetResult = HemGetSecretResult | HemGetPendingResult;
export type HemBatchResult = HemGetResult | HemBatchErrorResult;
export interface HemDeleteResult {
    deleted: boolean;
    approvalRequestId?: string;
    approvalState?: ApprovalState;
}
export interface HemApprovalRequestInfo {
    requestId: string;
    state: ApprovalState;
    secret: HemSecretRef;
    requesterTokenId?: string;
    requesterIdentityId?: string;
    requesterProject?: string;
    reason?: string;
    action?: string;
    createdAt?: string;
    resolvedAt?: string;
    resolvedBy?: string;
    resolveMessage?: string;
}
export declare class HemSdkError extends Error {
    readonly method: string;
    readonly code?: grpc.status;
    constructor(method: string, message: string, code?: grpc.status);
}
export declare class HemClient {
    private readonly client;
    private readonly token?;
    private readonly timeoutMs;
    constructor(options?: HemClientOptions);
    close(): void;
    get(secret: string, options?: HemGetOptions): Promise<HemGetResult>;
    getAll(requests: HemGetBatchRequest[]): Promise<HemBatchResult[]>;
    set(secret: string, values: Record<string, string>, options?: HemSetOptions): Promise<HemSecretInfo>;
    delete(secret: string, options?: HemDeleteOptions): Promise<HemDeleteResult>;
    getApprovalStatus(requestId: string): Promise<HemApprovalRequestInfo>;
    waitForApproval(requestId: string, options?: HemWaitForApprovalOptions): Promise<HemApprovalRequestInfo>;
    private metadata;
    private deadline;
    private unary;
}
export declare function createHemClient(options?: HemClientOptions): HemClient;
//# sourceMappingURL=index.d.ts.map