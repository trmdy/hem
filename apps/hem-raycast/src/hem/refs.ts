export const SLUG_RE = /^[a-z0-9-]+$/;

export type ScopeKind = "global" | "project" | "identity";

export interface SecretRefParts {
  scope: ScopeKind;
  project?: string;
  identityId?: string;
  name: string;
}

/** Wire shape of valhall.hem.v1.ScopeSelector (proto-loader, keepCase + string enums). */
export interface ProtoScopeSelector {
  scope: string;
  project?: string;
  identity_id?: string;
}

export interface ProtoSecretRef {
  scope: ProtoScopeSelector;
  name: string;
}

export function isValidSlug(s: string): boolean {
  return SLUG_RE.test(s);
}

/** Lowercase and coerce arbitrary input toward a valid hem slug ([a-z0-9-]+). */
export function slugify(input: string): string {
  return input
    .toLowerCase()
    .replace(/[\s_.]+/g, "-")
    .replace(/[^a-z0-9-]/g, "")
    .replace(/-{2,}/g, "-");
}

export function formatRef(ref: SecretRefParts): string {
  switch (ref.scope) {
    case "global":
      return `global/${ref.name}`;
    case "project":
      return `project/${ref.project}/${ref.name}`;
    case "identity":
      return `identity/${ref.identityId}/${ref.name}`;
  }
}

/**
 * Parse an explicit secret ref: global/<name>, project/<p>/<name>,
 * identity/<id>/<name>. Bare names are deliberately rejected — bare-name
 * resolution differs between read (identity→project→global) and write
 * (global), so callers must always be explicit.
 */
export function parseRef(input: string): SecretRefParts | null {
  const parts = input.trim().split("/");
  if (parts.length === 2 && parts[0] === "global") {
    const [, name] = parts;
    if (!isValidSlug(name)) return null;
    return { scope: "global", name };
  }
  if (parts.length === 3 && parts[0] === "project") {
    const [, project, name] = parts;
    if (!isValidSlug(project) || !isValidSlug(name)) return null;
    return { scope: "project", project, name };
  }
  if (parts.length === 3 && parts[0] === "identity") {
    const [, identityId, name] = parts;
    if (!isValidSlug(identityId) || !isValidSlug(name)) return null;
    return { scope: "identity", identityId, name };
  }
  return null;
}

export function refToProto(ref: SecretRefParts): ProtoSecretRef {
  switch (ref.scope) {
    case "global":
      return { scope: { scope: "SECRET_SCOPE_GLOBAL" }, name: ref.name };
    case "project":
      return { scope: { scope: "SECRET_SCOPE_PROJECT", project: ref.project }, name: ref.name };
    case "identity":
      return { scope: { scope: "SECRET_SCOPE_IDENTITY", identity_id: ref.identityId }, name: ref.name };
  }
}

export function protoToRef(scope: ProtoScopeSelector | undefined, name: string): SecretRefParts {
  switch (scope?.scope) {
    case "SECRET_SCOPE_PROJECT":
      return { scope: "project", project: scope.project || undefined, name };
    case "SECRET_SCOPE_IDENTITY":
      return { scope: "identity", identityId: scope.identity_id || undefined, name };
    default:
      return { scope: "global", name };
  }
}

/** Section key for grouping lists by scope: "global", "project/<p>", "identity/<id>". */
export function scopeSectionKey(ref: SecretRefParts): string {
  switch (ref.scope) {
    case "global":
      return "global";
    case "project":
      return `project/${ref.project}`;
    case "identity":
      return `identity/${ref.identityId}`;
  }
}
