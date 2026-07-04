import { describe, expect, it } from "vitest";
import { normalizeEnvKey, parseEnvText } from "../src/hem/env";

describe("parseEnvText", () => {
  it("parses plain KEY=VALUE lines and normalizes keys", () => {
    const entries = parseEnvText("ANTHROPIC_API_KEY=sk-ant-123\nDB_URL=postgres://x\n");
    expect(entries).toEqual([
      { originalKey: "ANTHROPIC_API_KEY", key: "anthropic_api_key", value: "sk-ant-123" },
      { originalKey: "DB_URL", key: "db_url", value: "postgres://x" },
    ]);
  });

  it("handles export prefixes and quotes", () => {
    const entries = parseEnvText(`export TOKEN="abc def"\nexport SINGLE='q u o'\n`);
    expect(entries[0]).toEqual({ originalKey: "TOKEN", key: "token", value: "abc def" });
    expect(entries[1].value).toBe("q u o");
  });

  it("skips comments, blanks, and lines without =", () => {
    const entries = parseEnvText("# comment\n\n// also comment\nnot a pair\nKEY=v\n");
    expect(entries).toHaveLength(1);
    expect(entries[0].key).toBe("key");
  });

  it("strips trailing unquoted comments but keeps quoted hashes", () => {
    const entries = parseEnvText(`A=value # trailing\nB="value # kept"\n`);
    expect(entries[0].value).toBe("value");
    expect(entries[1].value).toBe("value # kept");
  });

  it("skips empty values and keys with spaces", () => {
    const entries = parseEnvText("EMPTY=\nBAD KEY=x\nOK=1\n");
    expect(entries).toHaveLength(1);
    expect(entries[0].originalKey).toBe("OK");
  });

  it("handles CRLF input", () => {
    const entries = parseEnvText("A=1\r\nB=2\r\n");
    expect(entries).toHaveLength(2);
  });
});

describe("normalizeEnvKey", () => {
  it("lowercases and replaces invalid characters with underscores", () => {
    expect(normalizeEnvKey("MY-KEY.NAME")).toBe("my_key_name");
    expect(normalizeEnvKey("__weird__")).toBe("weird");
    expect(normalizeEnvKey("!!!")).toBe("value");
  });
});
