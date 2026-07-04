import { status as GrpcStatus } from "@grpc/grpc-js";

export type HemErrorKind =
  | "unreachable"
  | "unauthenticated"
  | "permission-denied"
  | "failed-precondition"
  | "not-found"
  | "invalid-argument"
  | "already-exists"
  | "timeout"
  | "unknown";

export class HemError extends Error {
  readonly kind: HemErrorKind;
  readonly grpcCode?: number;
  readonly method?: string;

  constructor(message: string, kind: HemErrorKind, opts: { grpcCode?: number; method?: string; cause?: unknown } = {}) {
    super(message, opts.cause !== undefined ? { cause: opts.cause } : undefined);
    this.name = "HemError";
    this.kind = kind;
    this.grpcCode = opts.grpcCode;
    this.method = opts.method;
  }
}

export function isHemError(e: unknown): e is HemError {
  return e instanceof HemError;
}

interface GrpcLikeError {
  code?: number;
  details?: string;
  message?: string;
}

const KIND_BY_CODE: Partial<Record<number, HemErrorKind>> = {
  [GrpcStatus.UNAVAILABLE]: "unreachable",
  [GrpcStatus.UNAUTHENTICATED]: "unauthenticated",
  [GrpcStatus.PERMISSION_DENIED]: "permission-denied",
  [GrpcStatus.FAILED_PRECONDITION]: "failed-precondition",
  [GrpcStatus.NOT_FOUND]: "not-found",
  [GrpcStatus.INVALID_ARGUMENT]: "invalid-argument",
  [GrpcStatus.ALREADY_EXISTS]: "already-exists",
  [GrpcStatus.DEADLINE_EXCEEDED]: "timeout",
};

export function classifyGrpcError(err: unknown, method: string): HemError {
  const e = (err ?? {}) as GrpcLikeError;
  const kind = (e.code !== undefined && KIND_BY_CODE[e.code]) || "unknown";
  const detail = e.details || e.message || "unknown gRPC error";
  return new HemError(`${method}: ${detail}`, kind, { grpcCode: e.code, method, cause: err });
}
