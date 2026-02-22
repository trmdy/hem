# @valhall/hem-sdk

TypeScript client for `hemd` gRPC API.

## Install (workspace)

```bash
npm install
```

## Usage

```ts
import { HemClient } from "@valhall/hem-sdk";

const hem = new HemClient();

const value = await hem.get("global/openai-prod", { key: "api_key" });
if (value.kind === "pending") {
  const status = await hem.waitForApproval(value.pending.requestId);
  console.log(status.state);
}

await hem.set("project/demo/service", { token: "abc" }, { actor: "sdk" });
await hem.delete("project/demo/service", { actor: "sdk" });

hem.close();
```

Default endpoint/token resolution:

- endpoint: `VALHALL_HEM_ADDR` -> `VALHALL_HEMD_ENDPOINT` -> `127.0.0.1:50091`
- token: `VALHALL_HEM_TOKEN`
