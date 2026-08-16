/// <reference types="@raycast/api">

/* 🚧 🚧 🚧
 * This file is auto-generated from the extension's manifest.
 * Do not modify manually. Instead, update the `package.json` file.
 * 🚧 🚧 🚧 */

/* eslint-disable @typescript-eslint/ban-types */

type ExtensionPreferences = {
  /** Daemon Endpoint - hemd gRPC endpoint. */
  "endpoint": string,
  /** Operator Token - Leave empty to auto-discover from the standard token file locations. */
  "token"?: string,
  /** Hem Binary - Path to the hem CLI, used for cluster commands only. */
  "hemBinary": string,
  /** Clipboard Clear (Seconds) - Clear copied secret values after this many seconds. 0 = never clear. */
  "clipboardClearSeconds": string,
  /** Primary Key Guess - Ordered, comma-separated key candidates for the Copy Primary Value action. */
  "primaryKeyGuess": string
}

/** Preferences accessible in all the extension's commands */
declare type Preferences = ExtensionPreferences

declare namespace Preferences {
  /** Preferences accessible in the `search-secrets` command */
  export type SearchSecrets = ExtensionPreferences & {}
  /** Preferences accessible in the `add-secret` command */
  export type AddSecret = ExtensionPreferences & {}
  /** Preferences accessible in the `cluster-status` command */
  export type ClusterStatus = ExtensionPreferences & {}
  /** Preferences accessible in the `pending-approvals` command */
  export type PendingApprovals = ExtensionPreferences & {}
  /** Preferences accessible in the `audit-log` command */
  export type AuditLog = ExtensionPreferences & {}
  /** Preferences accessible in the `scan-clipboard` command */
  export type ScanClipboard = ExtensionPreferences & {}
}

declare namespace Arguments {
  /** Arguments passed to the `search-secrets` command */
  export type SearchSecrets = {}
  /** Arguments passed to the `add-secret` command */
  export type AddSecret = {}
  /** Arguments passed to the `cluster-status` command */
  export type ClusterStatus = {}
  /** Arguments passed to the `pending-approvals` command */
  export type PendingApprovals = {}
  /** Arguments passed to the `audit-log` command */
  export type AuditLog = {}
  /** Arguments passed to the `scan-clipboard` command */
  export type ScanClipboard = {}
}

