#!/usr/bin/env node
// Copies hem.proto from the hem repo root into assets/ and records
// the source git revision in assets/hem.proto.rev (spec §3).
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const hemRepo = resolve(root, "../..");
const src = resolve(hemRepo, "proto/valhall/hem/v1/hem.proto");
const destDir = resolve(root, "assets");
const dest = resolve(destDir, "hem.proto");

mkdirSync(destDir, { recursive: true });
copyFileSync(src, dest);

const rev = execFileSync("git", ["-C", hemRepo, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
writeFileSync(resolve(destDir, "hem.proto.rev"), `${rev}\n`);

console.log(`synced ${src}`);
console.log(`  -> ${dest} @ ${rev}`);
