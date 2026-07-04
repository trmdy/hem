import { describe, expect, it } from "vitest";
import { formatRef, isValidSlug, parseRef, protoToRef, refToProto, scopeSectionKey, slugify } from "../src/hem/refs";

describe("parseRef / formatRef", () => {
  it("round-trips all three scopes", () => {
    for (const ref of ["global/anthropic", "project/globex/linear", "identity/tormod/github"]) {
      expect(formatRef(parseRef(ref)!)).toBe(ref);
    }
  });

  it("rejects bare names (bare-name read resolution differs from write)", () => {
    expect(parseRef("anthropic")).toBeNull();
  });

  it("rejects malformed and non-slug refs", () => {
    expect(parseRef("global/UPPER")).toBeNull();
    expect(parseRef("project/only-two")).toBeNull();
    expect(parseRef("identity/a/b/c")).toBeNull();
    expect(parseRef("secret/foo/bar")).toBeNull();
    expect(parseRef("global/")).toBeNull();
    expect(parseRef("")).toBeNull();
  });
});

describe("refToProto / protoToRef", () => {
  it("maps scopes to proto enum strings and back", () => {
    const project = refToProto({ scope: "project", project: "globex", name: "linear" });
    expect(project.scope.scope).toBe("SECRET_SCOPE_PROJECT");
    expect(project.scope.project).toBe("globex");
    expect(protoToRef(project.scope, project.name)).toEqual({ scope: "project", project: "globex", name: "linear" });

    const identity = refToProto({ scope: "identity", identityId: "tormod", name: "github" });
    expect(identity.scope.scope).toBe("SECRET_SCOPE_IDENTITY");
    expect(protoToRef(identity.scope, identity.name)).toEqual({ scope: "identity", identityId: "tormod", name: "github" });

    const global = refToProto({ scope: "global", name: "anthropic" });
    expect(global.scope.scope).toBe("SECRET_SCOPE_GLOBAL");
    expect(protoToRef(global.scope, global.name)).toEqual({ scope: "global", name: "anthropic" });
  });

  it("treats unspecified proto scope as global", () => {
    expect(protoToRef({ scope: "SECRET_SCOPE_UNSPECIFIED" }, "x").scope).toBe("global");
    expect(protoToRef(undefined, "x").scope).toBe("global");
  });
});

describe("slugify", () => {
  it("lowercases and dashes separators", () => {
    expect(slugify("My Fiken Key")).toBe("my-fiken-key");
    expect(slugify("API_KEY.v2")).toBe("api-key-v2");
    expect(slugify("weird!!chars")).toBe("weirdchars");
    expect(slugify("a--b")).toBe("a-b");
  });

  it("produces valid slugs for typical inputs", () => {
    for (const input of ["Fiken API", "hello_world", "x.y.z"]) {
      expect(isValidSlug(slugify(input))).toBe(true);
    }
  });
});

describe("scopeSectionKey", () => {
  it("groups by scope path", () => {
    expect(scopeSectionKey({ scope: "global", name: "x" })).toBe("global");
    expect(scopeSectionKey({ scope: "project", project: "globex", name: "x" })).toBe("project/globex");
    expect(scopeSectionKey({ scope: "identity", identityId: "tormod", name: "x" })).toBe("identity/tormod");
  });
});
