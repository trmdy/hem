import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
export const sdkName = "@valhall/hem-sdk";
const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_WAIT_POLL_INTERVAL_MS = 250;
const DEFAULT_WAIT_TIMEOUT_MS = 5 * 60 * 1_000;
const DEFAULT_PROTO_PATH = resolveDefaultProtoPath();
const OPERATOR_TOKEN_FILE = "operator.token";
const SECRET_SCOPE_GLOBAL = 1;
const SECRET_SCOPE_PROJECT = 2;
const SECRET_SCOPE_IDENTITY = 3;
const APPROVAL_STATE_PENDING = 1;
const APPROVAL_STATE_APPROVED = 2;
const APPROVAL_STATE_DENIED = 3;
const APPROVAL_STATE_TIMED_OUT = 4;
export class HemSdkError extends Error {
    method;
    code;
    constructor(method, message, code) {
        super(message);
        this.name = "HemSdkError";
        this.method = method;
        this.code = code;
    }
}
export class HemClient {
    client;
    token;
    timeoutMs;
    constructor(options = {}) {
        const endpoint = normalizeEndpoint(options.endpoint ?? resolveEndpointFromEnv());
        const token = normalizeOptional(options.token) ?? resolveTokenFromEnv();
        const protoPath = options.protoPath ?? DEFAULT_PROTO_PATH;
        const credentials = options.credentials ?? grpc.credentials.createInsecure();
        this.client = newHemRuntimeClient(endpoint, protoPath, credentials);
        this.token = token;
        this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    }
    close() {
        this.client.close();
    }
    async get(secret, options = {}) {
        const response = await this.unary("GetSecret", {
            secret: parseSecretReference(secret),
            context: toWireScopeContext(options),
            key: options.key ?? "",
            async_read: options.asyncRead ?? false,
            wait_timeout_ms: options.waitTimeoutMs ?? 0,
            reason: options.reason ?? "",
            approval_receipt: options.approvalReceipt ?? "",
        });
        return mapGetResult(response, options.key);
    }
    async getAll(requests) {
        if (requests.length === 0) {
            return [];
        }
        const response = await this.unary("GetSecrets", {
            requests: requests.map((item) => ({
                secret: parseSecretReference(item.secret),
                context: toWireScopeContext(item),
                key: item.key ?? "",
                async_read: item.asyncRead ?? false,
                wait_timeout_ms: item.waitTimeoutMs ?? 0,
                reason: item.reason ?? "",
            })),
        });
        return (response.results ?? []).map((item) => {
            const error = normalizeOptional(item.error);
            if (error) {
                return {
                    kind: "error",
                    error,
                };
            }
            return mapGetResult({
                secret: item.secret,
                pending: item.pending,
            }, undefined);
        });
    }
    async set(secret, values, options = {}) {
        const entries = Object.entries(values);
        if (entries.length === 0) {
            throw new HemSdkError("SetSecret", "values must include at least one key");
        }
        const response = await this.unary("SetSecret", {
            secret: parseSecretReference(secret),
            values: entries.map(([key, value]) => ({ key, value: String(value) })),
            description: options.description ?? "",
            requires_approval: options.requiresApproval ?? false,
            group: options.group ?? "",
            actor: options.actor ?? "",
            approval_receipt: options.approvalReceipt ?? "",
            reason: options.reason ?? "",
        });
        return mapSecretInfo(response);
    }
    async delete(secret, options = {}) {
        const response = await this.unary("DeleteSecret", {
            secret: parseSecretReference(secret),
            actor: options.actor ?? "",
            approval_receipt: options.approvalReceipt ?? "",
            reason: options.reason ?? "",
        });
        return {
            deleted: Boolean(response.deleted),
            approvalRequestId: normalizeOptional(response.approval_request_id),
            approvalState: mapApprovalState(response.approval_state),
        };
    }
    async getApprovalStatus(requestId) {
        const response = await this.unary("GetApprovalStatus", {
            request_id: requireNonEmpty("requestId", requestId),
        });
        const request = requireValue(response.request, "GetApprovalStatus.request");
        return mapApprovalRequestInfo(request);
    }
    async waitForApproval(requestId, options = {}) {
        const normalizedRequestId = requireNonEmpty("requestId", requestId);
        const timeoutMs = options.timeoutMs ?? DEFAULT_WAIT_TIMEOUT_MS;
        const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_WAIT_POLL_INTERVAL_MS;
        const deadline = Date.now() + timeoutMs;
        // Poll hemd until the approval request is resolved.
        for (;;) {
            const status = await this.getApprovalStatus(normalizedRequestId);
            if (status.state !== "pending") {
                return status;
            }
            if (Date.now() >= deadline) {
                throw new HemSdkError("WaitForApproval", `approval wait timed out: request_id=${normalizedRequestId}`, grpc.status.DEADLINE_EXCEEDED);
            }
            await sleep(pollIntervalMs);
        }
    }
    metadata() {
        const metadata = new grpc.Metadata();
        if (this.token) {
            metadata.set("authorization", `Bearer ${this.token}`);
        }
        return metadata;
    }
    deadline() {
        return new Date(Date.now() + this.timeoutMs);
    }
    async unary(method, payload) {
        const rpc = this.client[method];
        if (typeof rpc !== "function") {
            throw new HemSdkError(method, `RPC method unavailable: ${method}`);
        }
        return await new Promise((resolve, reject) => {
            rpc.call(this.client, payload, this.metadata(), { deadline: this.deadline() }, (error, response) => {
                if (error) {
                    reject(new HemSdkError(method, formatError(error), grpcCode(error)));
                    return;
                }
                resolve(response);
            });
        });
    }
}
export function createHemClient(options = {}) {
    return new HemClient(options);
}
function newHemRuntimeClient(endpoint, protoPath, credentials) {
    const packageDefinition = protoLoader.loadSync(protoPath, {
        keepCase: true,
        longs: String,
        enums: Number,
        defaults: true,
        oneofs: true,
        includeDirs: [dirname(protoPath), process.cwd()],
    });
    const loaded = grpc.loadPackageDefinition(packageDefinition);
    const HemRuntime = loaded.valhall?.hem?.v1?.HemRuntime;
    if (!HemRuntime) {
        throw new Error(`HemRuntime service not found in proto: ${protoPath}`);
    }
    return new HemRuntime(endpoint, credentials);
}
function resolveDefaultProtoPath() {
    const moduleProtoPath = fileURLToPath(new URL("../proto/valhall/hem/v1/hem.proto", import.meta.url));
    const candidates = [
        moduleProtoPath,
        resolve(process.cwd(), "packages/hem/proto/valhall/hem/v1/hem.proto"),
        resolve(process.cwd(), "sdks/typescript/packages/hem/proto/valhall/hem/v1/hem.proto"),
        resolve(process.cwd(), "proto/valhall/hem/v1/hem.proto"),
    ];
    for (const candidate of candidates) {
        if (existsSync(candidate)) {
            return candidate;
        }
    }
    return moduleProtoPath;
}
function resolveEndpointFromEnv() {
    const fromEnv = normalizeOptional(process.env.VALHALL_HEM_ADDR) ??
        normalizeOptional(process.env.VALHALL_HEMD_ENDPOINT);
    return fromEnv ?? "127.0.0.1:50091";
}
function resolveTokenFromEnv() {
    const envToken = normalizeOptional(process.env.VALHALL_HEM_TOKEN);
    if (envToken) {
        return envToken;
    }
    for (const path of operatorTokenFileCandidates()) {
        const token = readTokenFile(path);
        if (token) {
            return token;
        }
    }
    return undefined;
}
function operatorTokenFileCandidates() {
    const candidates = [];
    const hemDataDir = normalizeOptional(process.env.HEM_DATA_DIR);
    const systemDaemonsDir = normalizeOptional(process.env.VALHALL_SYSTEM_DAEMONS_DIR);
    const home = normalizeOptional(process.env.HOME);
    if (hemDataDir) {
        candidates.push(resolve(hemDataDir, OPERATOR_TOKEN_FILE));
    }
    if (systemDaemonsDir) {
        candidates.push(resolve(systemDaemonsDir, "data", "hem", OPERATOR_TOKEN_FILE));
    }
    if (home) {
        candidates.push(resolve(home, ".valhall", "hem", OPERATOR_TOKEN_FILE));
        candidates.push(resolve(home, ".valhall", "system-daemons", "data", "hem", OPERATOR_TOKEN_FILE));
    }
    return candidates;
}
function readTokenFile(path) {
    try {
        return normalizeOptional(readFileSync(path, "utf8"));
    }
    catch {
        return undefined;
    }
}
function normalizeEndpoint(endpoint) {
    const normalized = endpoint.trim().replace(/^https?:\/\//, "");
    return normalized.split("/")[0] || "127.0.0.1:50091";
}
function parseSecretReference(secretRef) {
    const normalized = requireNonEmpty("secretRef", secretRef);
    const parts = normalized.split("/");
    if (parts.length === 1) {
        return {
            scope: {
                scope: SECRET_SCOPE_GLOBAL,
                project: "",
                identity_id: "",
            },
            name: parts[0],
        };
    }
    if (parts.length === 2 && parts[0] === "global") {
        return {
            scope: {
                scope: SECRET_SCOPE_GLOBAL,
                project: "",
                identity_id: "",
            },
            name: requireNonEmpty("secret name", parts[1]),
        };
    }
    if (parts.length === 3 && parts[0] === "project") {
        return {
            scope: {
                scope: SECRET_SCOPE_PROJECT,
                project: requireNonEmpty("project", parts[1]),
                identity_id: "",
            },
            name: requireNonEmpty("secret name", parts[2]),
        };
    }
    if (parts.length === 3 && parts[0] === "identity") {
        return {
            scope: {
                scope: SECRET_SCOPE_IDENTITY,
                project: "",
                identity_id: requireNonEmpty("identityId", parts[1]),
            },
            name: requireNonEmpty("secret name", parts[2]),
        };
    }
    throw new HemSdkError("parseSecretReference", `expected <name>, global/<name>, project/<project>/<name>, or identity/<identityId>/<name>; got '${secretRef}'`, grpc.status.INVALID_ARGUMENT);
}
function toWireScopeContext(context) {
    return {
        identity_id: context.identityId ?? "",
        project: context.project ?? "",
    };
}
function mapGetResult(response, key) {
    if (response.pending) {
        return {
            kind: "pending",
            pending: mapPendingApproval(response.pending),
        };
    }
    const secret = requireValue(response.secret, "GetSecret.secret");
    const mapped = mapSecretWithValues(secret);
    return {
        kind: "secret",
        value: key ? mapped.values[key] : undefined,
        secret: mapped,
    };
}
function mapPendingApproval(value) {
    return {
        requestId: requireNonEmpty("pending.request_id", value.request_id ?? ""),
        state: mapApprovalState(value.state) ?? "pending",
        message: normalizeOptional(value.message),
    };
}
function mapSecretWithValues(value) {
    return {
        info: mapSecretInfo(requireValue(value.info, "SecretWithValues.info")),
        values: toStringMap(value.values),
    };
}
function mapSecretInfo(value) {
    return {
        scope: mapScopeSelector(value.scope),
        name: value.name,
        description: normalizeOptional(value.description),
        requiresApproval: Boolean(value.requires_approval),
        group: normalizeOptional(value.group),
        createdAt: normalizeOptional(value.created_at),
        updatedAt: normalizeOptional(value.updated_at),
        createdBy: normalizeOptional(value.created_by),
        lastAccessedAt: normalizeOptional(value.last_accessed_at),
        lastAccessedBy: normalizeOptional(value.last_accessed_by),
    };
}
function mapScopeSelector(value) {
    const scope = value?.scope ?? SECRET_SCOPE_GLOBAL;
    switch (scope) {
        case SECRET_SCOPE_PROJECT:
            return {
                scope: "project",
                project: normalizeOptional(value?.project),
            };
        case SECRET_SCOPE_IDENTITY:
            return {
                scope: "identity",
                identityId: normalizeOptional(value?.identity_id),
            };
        case SECRET_SCOPE_GLOBAL:
        default:
            return {
                scope: "global",
            };
    }
}
function mapSecretRef(value) {
    return {
        scope: mapScopeSelector(value.scope),
        name: value.name,
    };
}
function mapApprovalRequestInfo(value) {
    return {
        requestId: requireNonEmpty("request_id", value.request_id ?? ""),
        state: mapApprovalState(value.state) ?? "unspecified",
        secret: mapSecretRef(requireValue(value.secret, "ApprovalRequestInfo.secret")),
        requesterTokenId: normalizeOptional(value.requester_token_id),
        requesterIdentityId: normalizeOptional(value.requester_identity_id),
        requesterProject: normalizeOptional(value.requester_project),
        reason: normalizeOptional(value.reason),
        action: normalizeOptional(value.action),
        createdAt: normalizeOptional(value.created_at),
        resolvedAt: normalizeOptional(value.resolved_at),
        resolvedBy: normalizeOptional(value.resolved_by),
        resolveMessage: normalizeOptional(value.resolve_message),
    };
}
function mapApprovalState(state) {
    switch (state) {
        case APPROVAL_STATE_PENDING:
            return "pending";
        case APPROVAL_STATE_APPROVED:
            return "approved";
        case APPROVAL_STATE_DENIED:
            return "denied";
        case APPROVAL_STATE_TIMED_OUT:
            return "timed_out";
        default:
            return undefined;
    }
}
function toStringMap(value) {
    if (!value) {
        return {};
    }
    const out = {};
    for (const [key, item] of Object.entries(value)) {
        out[key] = String(item);
    }
    return out;
}
function normalizeOptional(value) {
    if (value === undefined) {
        return undefined;
    }
    const trimmed = value.trim();
    return trimmed.length === 0 ? undefined : trimmed;
}
function requireNonEmpty(name, value) {
    const normalized = normalizeOptional(value);
    if (!normalized) {
        throw new HemSdkError("validation", `${name} must not be empty`, grpc.status.INVALID_ARGUMENT);
    }
    return normalized;
}
function requireValue(value, field) {
    if (value === null || value === undefined) {
        throw new HemSdkError("response", `missing required response field: ${field}`);
    }
    return value;
}
function grpcCode(error) {
    const raw = error?.code;
    return typeof raw === "number" ? raw : undefined;
}
function formatError(error) {
    if (error instanceof Error) {
        return error.message;
    }
    return String(error);
}
function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
