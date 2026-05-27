#![allow(clippy::large_enum_variant)]

use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    fs,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use hem_core::{
    inspect_data_dir_security, node_statement_hash_b64, peer_transport_auth_statement_bytes,
    verify_node_statement_signature, ApprovalCredential, AuditEntry as CoreAuditEntry,
    ClusterConfig, ClusterInvite, CollisionAgreementStatement, HemStore, IssueOfflineLeaseInput,
    LedgerCollision, LedgerForkReplayInput, LedgerOperation, LedgerOperationBody,
    LedgerOperationEnvelope, LedgerStore, LedgerValueRewrapInput, LocalApprovalAdapter,
    LocalStoreLedgerMigrationInput, NodeIdentity, NodeKeyRecipient, OfflineLease, PeerConfig,
    PlatformBiometricApprovalAdapter, PolicyStore, SecretPolicyTier as CoreSecretPolicyTier,
};
use serde::Serialize;
use tonic::{
    codegen::InterceptedService,
    metadata::MetadataValue,
    service::Interceptor,
    transport::{Channel, Endpoint},
    Code, Request, Status,
};

pub mod proto {
    tonic::include_proto!("valhall.hem.v1");
}

use proto::{
    get_secret_request, get_secret_response, hem_runtime_client::HemRuntimeClient,
    DeleteSecretRequest, ExportSecretsRequest, GetAuditLogRequest, GetSecretRequest,
    GrantAccessRequest, HealthRequest, ImportSecretsRequest, InitHemRequest,
    IssueAgentTokenRequest, IssueServiceTokenRequest, ListActiveTokensRequest, ListGrantsRequest,
    ListPendingApprovalsRequest, ListSecretsRequest, PeerAckOperationsRequest,
    PeerApproveCollisionRequest, PeerHelloRequest, PeerListOperationsRequest,
    PeerPushOperationsRequest, ResolveApprovalRequest, RevokeAccessRequest, RevokeTokenRequest,
    RotateMasterKeyRequest, ScanForSecretsRequest, ScopeResolutionContext, ScopeSelector,
    SecretRef, SecretScope, SecretValue, SetSecretRequest,
};

const SECRET_REF_FORMATS: &str =
    "<name> (global), global/<name>, project/<project>/<name>, identity/<identity_id>/<name>";
const AUTHORIZATION_METADATA_KEY: &str = "authorization";
const DEFAULT_HEM_SUBDIR: &str = ".valhall/hem";
const DEFAULT_HEM_SYSTEM_DAEMONS_SUBDIR: &str = ".valhall/system-daemons/data/hem";
const DEFAULT_HEMD_BIND: &str = "127.0.0.1:50091";
const OPERATOR_TOKEN_FILE: &str = "operator.token";
const CLUSTER_CONFIG_FILE: &str = "cluster.toml";
const NODE_IDENTITY_FILE: &str = "node-identity.json";
const DEFAULT_SCAN_MIN_VALUE_LENGTH: u32 = 8;
const DEFAULT_SEARCH_LIMIT: u32 = 100;
const CLUSTER_PEER_CONNECT_TIMEOUT_SECS: u64 = 3;
const CLUSTER_PEER_RPC_TIMEOUT_SECS: u64 = 10;
const PEER_TRANSPORT_AUTH_CLUSTER_ID_METADATA_KEY: &str = "x-hem-peer-cluster-id";
const PEER_TRANSPORT_AUTH_NODE_ID_METADATA_KEY: &str = "x-hem-peer-node-id";
const PEER_TRANSPORT_AUTH_METHOD_METADATA_KEY: &str = "x-hem-peer-method";
const PEER_TRANSPORT_AUTH_NONCE_METADATA_KEY: &str = "x-hem-peer-nonce";
const PEER_TRANSPORT_AUTH_TIMESTAMP_METADATA_KEY: &str = "x-hem-peer-timestamp";
const PEER_TRANSPORT_AUTH_SIGNATURE_METADATA_KEY: &str = "x-hem-peer-signature";
const PEER_METHOD_APPROVE_COLLISION: &str = "PeerApproveCollision";
const PEER_METHOD_HELLO: &str = "PeerHello";
const PEER_METHOD_LIST_OPERATIONS: &str = "PeerListOperations";
const PEER_METHOD_PUSH_OPERATIONS: &str = "PeerPushOperations";
const PEER_METHOD_ACK_OPERATIONS: &str = "PeerAckOperations";

#[derive(Debug, Parser)]
#[command(
    name = "hem",
    about = "Valhall Hem secret-management CLI",
    long_about = "Agent-first CLI for the hemd secret vault daemon.",
    after_help = "Secret reference formats:\n  <name> (implies global)\n  global/<name>\n  project/<project>/<name>\n  identity/<identity_id>/<name>\n\nQuick examples:\n  hem set openai-prod api_key=...            # global/openai-prod\n  hem get project/acme/openai-prod api_key\n  hem search 'project/*/openai-*'\n  hem archive global/openai-prod\n\nDelete approval flow:\n  hem delete global/openai-prod\n  hem approvals\n  hem approve <request-id>                   # interactive human confirm\n  hem delete global/openai-prod --approval-receipt <receipt>\n\nAuth token resolution:\n  --token <token> -> VALHALL_HEM_TOKEN -> $HEM_DATA_DIR/operator.token -> ~/.valhall/hem/operator.token -> ~/.valhall/system-daemons/data/hem/operator.token\n\nEndpoint selection:\n  --endpoint <url> or VALHALL_HEMD_ENDPOINT"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "Hem daemon endpoint (default: http://127.0.0.1:50091; env: VALHALL_HEMD_ENDPOINT)"
    )]
    endpoint: Option<String>,
    #[arg(
        long,
        global = true,
        help = "Bearer token for hemd auth (env: VALHALL_HEM_TOKEN; fallback operator.token in HEM_DATA_DIR, ~/.valhall/hem, or ~/.valhall/system-daemons/data/hem)"
    )]
    token: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(visible_alias = "h")]
    Health,
    #[command(visible_alias = "i")]
    Init {
        #[arg(long)]
        force: bool,
    },
    #[command(
        about = "Create or update a secret",
        after_help = "Examples:\n  hem set openai-prod api_key=... model=gpt-4.1\n  hem set project/acme/cloudflare token=...\n  hem set identity/agent-123/github token=... --requires-approval\n  hem set openai-prod --interactive\n  hem set openai-prod api_key=op://Personal/openai-prod/api_key\n  hem set openai-prod --from-op-item op://Personal/openai-prod\n\nIf set returns approval_required, approve then retry:\n  hem approvals\n  hem approve <request-id>\n  hem set openai-prod api_key=... --approval-receipt <receipt>\n\nNotes:\n  - Secret names must be lowercase, digits, and hyphen only.\n  - Secret values are key=value pairs.\n  - Values prefixed with op:// are resolved via `op read`.\n  - --from-op-item imports all non-empty fields from a 1Password item."
    )]
    #[command(visible_alias = "s")]
    Set {
        #[arg(
            value_name = "SECRET",
            help = "Secret reference",
            long_help = "Secret reference. Accepted formats:\n  <name> (implies global)\n  global/<name>\n  project/<project>/<name>\n  identity/<identity_id>/<name>"
        )]
        secret: String,
        #[arg(
            value_name = "KEY=VALUE",
            help = "One or more key=value pairs",
            required_unless_present_any = ["interactive", "from_op_item"]
        )]
        values: Vec<String>,
        #[arg(
            long,
            help = "Prompt for secret values interactively (values not passed on command line/history; merges with existing keys when the secret already exists)"
        )]
        interactive: bool,
        #[arg(
            long,
            value_name = "ITEM",
            help = "Import all fields from a 1Password item (item name/ID or op://<vault>/<item>)",
            conflicts_with = "interactive"
        )]
        from_op_item: Option<String>,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long)]
        requires_approval: bool,
        #[arg(long)]
        group: Option<String>,
        #[arg(long, default_value = "hem-cli")]
        actor: String,
        #[arg(long)]
        approval_receipt: Option<String>,
        #[arg(long, default_value = "")]
        reason: String,
    },
    #[command(
        about = "Read a secret by name or full reference",
        after_help = "Examples:\n  hem get openai-prod\n  hem get project/acme/openai-prod api_key\n  hem get openai-prod api_key --project acme\n\nIf KEY is provided, stdout is the raw value only (no metadata).\n\nIf get returns pending_request_id:\n  hem approvals\n  hem approve <request-id>\n  hem get openai-prod --approval-receipt <receipt>\n\nIf SECRET is unscoped (<name>), resolution is identity -> project -> global."
    )]
    #[command(visible_alias = "g")]
    Get {
        #[arg(
            value_name = "SECRET",
            help = "Secret name or scoped reference",
            long_help = "Secret name or scoped reference. Use <name> for scope resolution, or explicit formats:\n  global/<name>\n  project/<project>/<name>\n  identity/<identity_id>/<name>"
        )]
        secret: String,
        key: Option<String>,
        #[arg(long)]
        identity_id: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        approval_receipt: Option<String>,
        #[arg(long, default_value = "")]
        reason: String,
    },
    #[command(
        about = "Scan stdin for leaked secret values",
        visible_alias = "sc",
        after_help = "Reads text from stdin and checks whether any Hem secret values appear as substrings.\n\nExit codes:\n  0 clean\n  1 one or more secret values detected\n  2 scan error (auth/rpc/invalid input)"
    )]
    Scan {
        #[arg(
            long,
            value_name = "SCOPE",
            help = "Limit scan to: global | project/<project> | identity/<identity_id>"
        )]
        scope: Option<String>,
        #[arg(long, default_value_t = DEFAULT_SCAN_MIN_VALUE_LENGTH)]
        min_length: u32,
        #[arg(long, short = 'q')]
        quiet: bool,
        #[arg(long)]
        json: bool,
    },
    #[command(
        about = "Search secrets by name/scope/group/description",
        visible_aliases = ["list", "ls", "l"],
        after_help = "Wildcard search:\n  '*' matches any chars\n  '?' matches one char\n\nExamples:\n  hem ls                             # same as hem ls '*'\n  hem search openai\n  hem search 'project/*/openai-*'\n  hem search 'identity/*/github'\n\nTip: quote wildcard patterns so the shell does not expand them."
    )]
    Search {
        #[arg(
            value_name = "QUERY",
            help = "Query text; supports '*' and '?' wildcards",
            default_value = "*"
        )]
        query: String,
        #[arg(long, default_value_t = DEFAULT_SEARCH_LIMIT)]
        limit: u32,
        #[arg(
            short = 'p',
            long,
            help = "Split project results into project/<project> sections"
        )]
        group_projects: bool,
    },
    #[command(
        about = "Archive a secret to local JSON",
        after_help = "Default output path:\n  $VALHALL_HEM_ARCHIVE_DIR or ~/.valhall/hem/archive\n\nExample:\n  hem archive global/openai-prod\n  hem archive project/acme/openai-prod -o /tmp/openai.json"
    )]
    #[command(visible_alias = "ar")]
    Archive {
        #[arg(
            value_name = "SECRET",
            help = "Scoped secret reference",
            long_help = "Scoped secret reference. Accepted formats:\n  <name> (implies global)\n  global/<name>\n  project/<project>/<name>\n  identity/<identity_id>/<name>"
        )]
        secret: String,
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    #[command(
        about = "Delete a secret (approval workflow enforced server-side)",
        after_help = "Flow:\n  1) hem delete <secret>\n  2) hem approvals\n  3) hem approve <request-id>           # interactive typed confirmation\n  4) hem delete <secret> --approval-receipt <receipt>"
    )]
    #[command(visible_aliases = ["del", "rm"])]
    Delete {
        #[arg(
            value_name = "SECRET",
            help = "Scoped secret reference",
            long_help = "Scoped secret reference. Accepted formats:\n  <name> (implies global)\n  global/<name>\n  project/<project>/<name>\n  identity/<identity_id>/<name>"
        )]
        secret: String,
        #[arg(long, default_value = "hem-cli")]
        actor: String,
        #[arg(long)]
        approval_receipt: Option<String>,
        #[arg(long, default_value = "")]
        reason: String,
    },
    #[command(about = "List pending approval requests", visible_aliases = ["ap", "pending"])]
    Approvals {
        #[arg(long, default_value_t = 200)]
        limit: u32,
    },
    #[command(
        about = "Approve a pending request (interactive human confirmation)",
        visible_aliases = ["approve-delete", "ok"],
        after_help = "This command must run in an interactive terminal. You must type:\n  APPROVE <request-id>"
    )]
    Approve {
        request_id: String,
        #[arg(
            long,
            help = "Require local platform biometric approval before resolving the request"
        )]
        biometric: bool,
        #[arg(long, default_value = "hem-cli")]
        actor: String,
        #[arg(long, default_value = "")]
        message: String,
    },
    #[command(
        about = "Deny a pending request (interactive human confirmation)",
        visible_aliases = ["deny-delete", "no"],
        after_help = "This command must run in an interactive terminal. You must type:\n  DENY <request-id>"
    )]
    Deny {
        request_id: String,
        #[arg(long, default_value = "hem-cli")]
        actor: String,
        #[arg(long, default_value = "")]
        message: String,
    },
    #[command(
        about = "Manage local read policy tiers",
        after_help = "Examples:\n  hem policy list\n  hem policy get --secret global/openai-prod\n  hem policy set peer_quorum --scope global\n  hem policy set master_biometric --secret global/root-token"
    )]
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    #[command(
        about = "Issue, list, consume, and revoke local offline leases",
        after_help = "Examples:\n  hem lease issue global/openai-prod --requester token:abc --node-id hmn_local --uses 2 --ttl-seconds 600\n  hem lease list\n  hem lease revoke hol_..."
    )]
    Lease {
        #[command(subcommand)]
        command: LeaseCommands,
    },
    #[command(about = "Issue/list/revoke Hem access tokens", visible_alias = "t")]
    Token {
        #[command(subcommand)]
        command: TokenCommands,
    },
    #[command(
        about = "Manage standalone Hem cluster configuration",
        after_help = "These commands operate on local Hem data files and do not require hemd to be running.\n\nExamples:\n  hem cluster init --node-id hmn_local --listen 127.0.0.1:50191 --quorum 1\n  hem cluster status\n  hem cluster peers"
    )]
    Cluster {
        #[command(subcommand)]
        command: ClusterCommands,
    },
    #[command(
        about = "Grant explicit cross-scope access to a secret",
        after_help = "Examples:\n  hem grant-access project/acme/cloudflare-prod --grantee-scope global --grantee-id smi\n  hem grant-access identity/agent-123/github --grantee-scope identity/agent-123 --grantee-id agent-123"
    )]
    #[command(visible_aliases = ["ga", "grant"])]
    GrantAccess {
        secret: String,
        #[arg(
            long,
            value_name = "SCOPE",
            help = "global | project/<project> | identity/<identity_id>"
        )]
        grantee_scope: String,
        #[arg(long)]
        grantee_id: String,
        #[arg(long, default_value = "hem-cli")]
        actor: String,
    },
    #[command(
        about = "Revoke explicit grant for a secret",
        after_help = "Example:\n  hem revoke-access project/acme/cloudflare-prod --grantee-scope global --grantee-id smi"
    )]
    #[command(visible_aliases = ["ra", "revoke"])]
    RevokeAccess {
        secret: String,
        #[arg(
            long,
            value_name = "SCOPE",
            help = "global | project/<project> | identity/<identity_id>"
        )]
        grantee_scope: String,
        #[arg(long)]
        grantee_id: String,
        #[arg(long, default_value = "hem-cli")]
        actor: String,
    },
    #[command(about = "List explicit grants for a secret", visible_aliases = ["grants", "lg"])]
    ListGrants { secret: String },
    #[command(
        about = "Read Hem audit log",
        after_help = "Examples:\n  hem audit\n  hem audit --scope project/acme --since 2026-02-21T00:00:00Z --limit 100"
    )]
    #[command(visible_aliases = ["au", "log"])]
    Audit {
        #[arg(long, value_name = "SCOPE")]
        scope: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value_t = 200)]
        limit: u32,
    },
    #[command(
        about = "Export secrets to encrypted bundle bytes",
        after_help = "Examples:\n  hem export\n  hem export --scope project/acme -o /tmp/hem-export.bin"
    )]
    #[command(visible_aliases = ["ex", "dump"])]
    Export {
        #[arg(long, value_name = "SCOPE")]
        scope: Option<String>,
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    #[command(
        about = "Import secrets from encrypted bundle bytes",
        after_help = "Examples:\n  hem import -i /tmp/hem-export.bin\n  hem import -i /tmp/hem-export.bin --merge"
    )]
    #[command(visible_aliases = ["im", "load"])]
    Import {
        #[arg(short = 'i', long, value_name = "PATH")]
        input: String,
        #[arg(long)]
        merge: bool,
        #[arg(long, default_value = "hem-cli")]
        actor: String,
    },
    #[command(
        about = "Rotate Hem master key and re-encrypt secrets",
        after_help = "Example:\n  hem rotate --actor operator"
    )]
    #[command(visible_aliases = ["ro", "rk"])]
    Rotate {
        #[arg(long, default_value = "hem-cli")]
        actor: String,
    },
    #[command(
        about = "Print canonical Hem command examples for agents",
        after_help = "Machine-readable by default.\n\nExamples:\n  hem examples\n  hem examples --format json | jq .\n  hem examples --format shell"
    )]
    #[command(visible_aliases = ["eg", "x"])]
    Examples {
        #[arg(long, value_enum, default_value_t = ExamplesFormat::Json)]
        format: ExamplesFormat,
    },
    #[command(visible_alias = "u")]
    Usage,
}

#[derive(Debug, Subcommand)]
enum PolicyCommands {
    #[command(about = "List configured default, scope, and secret policy tiers")]
    List,
    #[command(about = "Get the effective policy for default, scope, or secret")]
    Get {
        #[arg(long, conflicts_with = "secret")]
        scope: Option<String>,
        #[arg(long, conflicts_with = "scope")]
        secret: Option<String>,
    },
    #[command(about = "Set policy tier for default, scope, or secret")]
    Set {
        tier: String,
        #[arg(long, conflicts_with = "secret")]
        scope: Option<String>,
        #[arg(long, conflicts_with = "scope")]
        secret: Option<String>,
        #[arg(long, help = "Required when lowering the effective policy tier")]
        allow_downgrade: bool,
    },
}

#[derive(Debug, Subcommand)]
enum LeaseCommands {
    #[command(about = "Issue an offline lease bound to a secret, requester, and node")]
    Issue {
        secret: String,
        #[arg(long)]
        requester: String,
        #[arg(long)]
        node_id: String,
        #[arg(long, default_value_t = 1)]
        uses: u32,
        #[arg(long, default_value_t = 600)]
        ttl_seconds: i64,
    },
    #[command(about = "List offline leases")]
    List,
    #[command(about = "Consume one offline lease use")]
    Consume {
        secret: String,
        #[arg(long)]
        requester: String,
        #[arg(long)]
        node_id: String,
    },
    #[command(about = "Revoke an offline lease")]
    Revoke {
        lease_id: String,
        #[arg(long, default_value = "hem-cli")]
        actor: String,
    },
}

#[derive(Debug, Subcommand)]
enum TokenCommands {
    #[command(about = "Issue a service token", visible_aliases = ["is", "service"])]
    IssueService {
        service_name: String,
        #[arg(long)]
        ttl_seconds: Option<u64>,
        #[arg(long, default_value = "hem-cli")]
        issued_by: String,
    },
    #[command(about = "Issue an agent token", visible_aliases = ["ia", "agent"])]
    IssueAgent {
        #[arg(long)]
        identity_id: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long, value_enum, value_delimiter = ',')]
        scopes: Vec<TokenScopeArg>,
        #[arg(long)]
        ttl_seconds: Option<u64>,
        #[arg(long, default_value = "hem-cli")]
        issued_by_service: String,
    },
    #[command(about = "List active tokens", visible_aliases = ["ls", "l"])]
    List {
        #[arg(long, value_enum)]
        token_type: Option<TokenTypeArg>,
        #[arg(long)]
        service_name: Option<String>,
        #[arg(long)]
        identity_id: Option<String>,
        #[arg(long, default_value_t = 200)]
        limit: u32,
    },
    #[command(about = "Revoke a token by token_id", visible_aliases = ["rv", "rm"])]
    Revoke {
        token_id: String,
        #[arg(long, default_value = "hem-cli")]
        actor: String,
    },
}

#[derive(Debug, Subcommand)]
enum ClusterCommands {
    #[command(about = "Initialize standalone cluster config and node identity")]
    Init {
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        listen: String,
        #[arg(long, default_value_t = 1)]
        quorum: u16,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        master_node_id: Option<String>,
        #[arg(long)]
        force: bool,
    },
    #[command(about = "Print local cluster config status")]
    Status,
    #[command(about = "Print machine-readable cluster health, lag, and risk status")]
    Health,
    #[command(about = "List static cluster peers from local config")]
    Peers,
    #[command(about = "Create a signed invite for another Hem node")]
    Invite {
        #[arg(long, default_value_t = 3600)]
        ttl_seconds: u64,
    },
    #[command(about = "Manage static cluster peers")]
    Peer {
        #[command(subcommand)]
        command: ClusterPeerCommands,
    },
    #[command(about = "Synchronize distributed ledger operations with configured peers")]
    Sync {
        #[arg(long)]
        once: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        peer: Option<String>,
        #[arg(long, default_value_t = 1000)]
        limit: u32,
    },
    #[command(about = "Bootstrap local ledger history from a configured peer")]
    BootstrapLedger {
        #[arg(long)]
        peer: Option<String>,
        #[arg(long, default_value_t = 1000)]
        limit: u32,
    },
    #[command(about = "Install hem/hemd from a release artifact and write supervisor files")]
    Install {
        #[arg(long)]
        artifact_dir: String,
        #[arg(long)]
        prefix: String,
        #[arg(long)]
        data_dir: String,
        #[arg(long, default_value = DEFAULT_HEMD_BIND)]
        bind: String,
        #[arg(long, value_enum, default_value_t = ClusterSupervisorKind::Launchd)]
        supervisor: ClusterSupervisorKind,
        #[arg(long)]
        force: bool,
    },
    #[command(about = "Rebuild an existing hem/hemd install from a release artifact with backup")]
    Rebuild {
        #[arg(long)]
        artifact_dir: String,
        #[arg(long)]
        prefix: String,
        #[arg(long)]
        data_dir: String,
        #[arg(long, default_value = DEFAULT_HEMD_BIND)]
        bind: String,
        #[arg(long, value_enum, default_value_t = ClusterSupervisorKind::Launchd)]
        supervisor: ClusterSupervisorKind,
        #[arg(long)]
        backup_dir: String,
    },
    #[command(about = "Migrate existing local Hem secrets into the distributed ledger")]
    Migrate {
        #[arg(long)]
        dry_run: bool,
    },
    #[command(about = "Rewrap decryptable latest ledger values to all configured node keys")]
    RewrapValues {
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value = "hem-cli")]
        actor: String,
    },
    #[command(about = "Verify local distributed ledger integrity")]
    Verify {
        #[arg(long)]
        repair: bool,
    },
    #[command(about = "Declare an explicit hard fork from a parent checkpoint")]
    Fork {
        #[arg(long)]
        parent_checkpoint: Option<String>,
        #[arg(long, default_value = "hem-cli")]
        actor: String,
        #[arg(long)]
        reason: String,
    },
    #[command(about = "Execute a hard-fork materializer rewind and replay")]
    ReplayFork {
        fork_id: String,
        #[arg(long)]
        confirm_rewind: Option<String>,
        #[arg(long)]
        backup_confirmed: Option<String>,
        #[arg(long, default_value = "hem-cli")]
        actor: String,
    },
    #[command(about = "List unresolved distributed secret write collisions")]
    Collisions,
    #[command(about = "Append a signed collision resolution operation")]
    ResolveCollision {
        collision_id: String,
        #[arg(long, default_value = "keep-current")]
        resolution: String,
        #[arg(long, default_value = "hem-cli")]
        actor: String,
        #[arg(long)]
        allow_local: bool,
    },
    #[command(about = "Accept a cluster invite placeholder for the standalone flow")]
    Join {
        #[arg(value_name = "INVITE")]
        invite: String,
        #[arg(long)]
        node_id: Option<String>,
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ClusterSupervisorKind {
    Launchd,
    Systemd,
    None,
}

impl ClusterSupervisorKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Launchd => "launchd",
            Self::Systemd => "systemd",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Subcommand)]
enum ClusterPeerCommands {
    Add {
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        wrap_public_key: Option<String>,
    },
    Update {
        node_id: String,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        public_key: Option<String>,
        #[arg(long)]
        wrap_public_key: Option<String>,
    },
    Remove {
        node_id: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TokenScopeArg {
    Global,
    Project,
    Identity,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TokenTypeArg {
    Operator,
    Service,
    AgentRun,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ExamplesFormat {
    Json,
    Shell,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let scan_command = matches!(cli.command, Commands::Scan { .. });
    match run(cli).await {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(if scan_command { 2 } else { 1 });
        }
    }
}

async fn run(cli: Cli) -> Result<i32, Box<dyn std::error::Error>> {
    if let Commands::Examples { format } = &cli.command {
        print_examples(*format)?;
        return Ok(0);
    }
    if let Commands::Usage = &cli.command {
        print_usage();
        return Ok(0);
    }
    if let Commands::Cluster { command } = cli.command {
        return run_cluster_command(command).await;
    }
    if let Commands::Policy { command } = cli.command {
        return run_policy_command(command);
    }
    if let Commands::Lease { command } = cli.command {
        return run_lease_command(command);
    }

    let endpoint = daemon_endpoint(cli.endpoint);
    let auth_token = resolve_auth_token(cli.token);
    let mut client = connect_client(endpoint.as_str(), auth_token).await?;

    match cli.command {
        Commands::Health => {
            let response = client.health(HealthRequest {}).await?.into_inner();
            print_kv("status", response.status);
            print_kv("version", response.version);
        }
        Commands::Init { force } => {
            let response = client
                .init_hem(InitHemRequest { force })
                .await?
                .into_inner();
            print_kv("initialized", response.initialized);
            if !response.operator_token.is_empty() {
                print_kv("operator_token", response.operator_token);
            }
        }
        Commands::Set {
            secret,
            values,
            interactive,
            from_op_item,
            description,
            requires_approval,
            group,
            actor,
            approval_receipt,
            reason,
        } => {
            let secret_ref = parse_secret_ref_or_global(secret.as_str())?;
            let existing = if interactive {
                fetch_existing_secret_values(&mut client, &secret_ref).await?
            } else {
                Vec::new()
            };
            let imported = if let Some(item_ref) = from_op_item {
                read_op_item_values(item_ref.as_str())?
            } else {
                Vec::new()
            };
            let explicit = if interactive {
                collect_interactive_values(values)?
            } else if values.is_empty() {
                Vec::new()
            } else {
                parse_values(values)?
            };
            let values = build_set_values(existing, imported, explicit);
            if values.is_empty() {
                return Err("at least one key=value pair required".into());
            }
            let response = client
                .set_secret(SetSecretRequest {
                    secret: Some(secret_ref),
                    values,
                    description,
                    requires_approval,
                    group: group.unwrap_or_default(),
                    actor,
                    approval_receipt: approval_receipt.unwrap_or_default(),
                    reason,
                })
                .await?
                .into_inner();
            print_kv("name", response.name);
            print_kv(
                "scope",
                format_scope(response.scope.as_ref().unwrap_or(&ScopeSelector {
                    scope: SecretScope::Global as i32,
                    project: String::new(),
                    identity_id: String::new(),
                })),
            );
            print_kv("updated_at", response.updated_at);
        }
        Commands::Get {
            secret,
            key,
            identity_id,
            project,
            approval_receipt,
            reason,
        } => {
            let requested_key = key.and_then(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            });
            let lookup = parse_lookup(secret.as_str())?;
            let response = client
                .get_secret(GetSecretRequest {
                    lookup: Some(lookup),
                    context: Some(ScopeResolutionContext {
                        identity_id: identity_id.unwrap_or_default(),
                        project: project.unwrap_or_default(),
                    }),
                    key: requested_key.clone().unwrap_or_default(),
                    async_read: false,
                    wait_timeout_ms: 0,
                    reason,
                    approval_receipt: approval_receipt.unwrap_or_default(),
                })
                .await?
                .into_inner();

            match response.result {
                Some(get_secret_response::Result::Secret(secret)) => {
                    if let Some(requested_key) = requested_key.as_deref() {
                        println!("{}", required_secret_key_value(&secret, requested_key)?);
                    } else {
                        let info = secret.info.ok_or("missing secret info in get response")?;
                        print_kv("name", info.name);
                        if let Some(scope) = info.scope.as_ref() {
                            print_kv("scope", format_scope(scope));
                        }
                        print_table_header(&["KEY", "VALUE"]);
                        let mut entries = secret.values.into_iter().collect::<Vec<_>>();
                        entries.sort_by(|left, right| left.0.cmp(&right.0));
                        for (entry_key, entry_value) in entries {
                            println!("{entry_key}={entry_value}");
                        }
                    }
                }
                Some(get_secret_response::Result::Pending(pending)) => {
                    print_kv("pending_request_id", pending.request_id);
                    print_kv("message", pending.message);
                }
                None => return Err("missing get response result".into()),
            }
        }
        Commands::Scan {
            scope,
            min_length,
            quiet,
            json,
        } => {
            let mut text = String::new();
            io::stdin().read_to_string(&mut text)?;
            let scope = scope
                .map(|value| parse_scope_selector_value(value.as_str()))
                .transpose()?;
            let response = client
                .scan_for_secrets(ScanForSecretsRequest {
                    text,
                    scope,
                    min_value_length: min_length,
                })
                .await?
                .into_inner();

            if json {
                let payload = ScanOutput {
                    clean: response.clean,
                    matches: response
                        .matches
                        .into_iter()
                        .map(|item| ScanOutputMatch {
                            secret: item.secret_ref,
                            key: item.key,
                            offset: item.offset,
                        })
                        .collect(),
                    scanned_length: response.scanned_length,
                    secrets_checked: response.secrets_checked,
                };
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else if !quiet {
                for item in &response.matches {
                    println!("match   {} (key: {})", item.secret_ref, item.key);
                }
                if response.clean {
                    println!("result  clean");
                } else {
                    println!("result  {} secrets detected", response.matches.len());
                }
            }

            if !response.clean {
                return Ok(1);
            }
        }
        Commands::Search {
            query,
            limit,
            group_projects,
        } => {
            let query = normalize_query(query.as_str())?;
            let color_enabled = color_output_enabled();
            let response = client
                .list_secrets(ListSecretsRequest {
                    scope: None,
                    group: String::new(),
                    prefix: String::new(),
                    limit: search_request_limit(),
                })
                .await?
                .into_inner();

            let results =
                collect_search_results(response.secrets, query.as_str(), limit, group_projects);
            for (index, section) in results.sections.iter().enumerate() {
                if index > 0 {
                    println!();
                }
                println!(
                    "{}",
                    colorize(color_enabled, section.heading.as_str(), "1;34")
                );
                for secret in &section.secrets {
                    print_search_secret(secret, color_enabled);
                }
            }

            if results.matched == 0 {
                println!("no matches");
            } else if let Some(summary) = search_truncation_summary(results.shown, results.matched)
            {
                println!("{summary}");
            } else {
                print_kv("matches", results.matched);
            }
        }
        Commands::Archive { secret, output } => {
            let secret_ref = parse_secret_ref_or_global(secret.as_str())?;
            let scope = secret_ref
                .scope
                .as_ref()
                .ok_or("secret scope is required")?
                .clone();
            let secret_name = secret_ref.name.clone();

            let response = client
                .get_secret(GetSecretRequest {
                    lookup: Some(get_secret_request::Lookup::Secret(secret_ref)),
                    context: Some(ScopeResolutionContext {
                        identity_id: String::new(),
                        project: String::new(),
                    }),
                    key: String::new(),
                    async_read: false,
                    wait_timeout_ms: 0,
                    reason: String::new(),
                    approval_receipt: String::new(),
                })
                .await?
                .into_inner();

            let secret = match response.result {
                Some(get_secret_response::Result::Secret(secret)) => secret,
                Some(get_secret_response::Result::Pending(pending)) => {
                    return Err(format!(
                        "secret access pending approval request_id={}",
                        pending.request_id
                    )
                    .into())
                }
                None => return Err("missing get response result".into()),
            };

            let info = secret
                .info
                .ok_or("missing secret info in archive response")?;
            let scope_string = format_scope(&scope);
            let archive = ArchiveFile {
                version: "hem-archive-v1".to_string(),
                archived_at_epoch_ms: now_epoch_ms(),
                secret: ArchivedSecret {
                    scope: scope_string.clone(),
                    name: secret_name.clone(),
                    description: info.description,
                    requires_approval: info.requires_approval,
                    group: normalize_optional_string(info.group),
                    created_at: info.created_at,
                    updated_at: info.updated_at,
                    created_by: info.created_by,
                    last_accessed_at: normalize_optional_string(info.last_accessed_at),
                    last_accessed_by: normalize_optional_string(info.last_accessed_by),
                    values: secret.values,
                },
            };

            let output = match output {
                Some(value) => PathBuf::from(value),
                None => default_archive_path(scope_string.as_str(), secret_name.as_str()),
            };
            write_secure_json(output.as_path(), &archive)?;
            print_kv("archived", output.display());
        }
        Commands::Delete {
            secret,
            actor,
            approval_receipt,
            reason,
        } => {
            let secret_ref = parse_secret_ref_or_global(secret.as_str())?;
            let response = client
                .delete_secret(DeleteSecretRequest {
                    secret: Some(secret_ref),
                    actor,
                    approval_receipt: approval_receipt.unwrap_or_default(),
                    reason,
                })
                .await?
                .into_inner();
            if response.deleted {
                print_kv("deleted", true);
                if !response.approval_request_id.trim().is_empty() {
                    print_kv("approval_request_id", response.approval_request_id);
                }
            } else if !response.approval_request_id.trim().is_empty() {
                print_kv("deleted", false);
                print_kv("approval_required", true);
                print_kv("request_id", response.approval_request_id.as_str());
                print_kv(
                    "next",
                    format!("hem approve {}", response.approval_request_id),
                );
                print_kv(
                    "then",
                    format!("hem delete {} --approval-receipt <receipt>", secret.trim()),
                );
            } else {
                print_kv("deleted", false);
            }
        }
        Commands::Approvals { limit } => {
            let response = client
                .list_pending_approvals(ListPendingApprovalsRequest { limit })
                .await?
                .into_inner();
            if response.requests.is_empty() {
                println!("no pending approvals");
            } else {
                let pending_count = response.requests.len();
                for item in response.requests {
                    let action = if item.action.trim().is_empty() {
                        "unknown"
                    } else {
                        item.action.as_str()
                    };
                    if let Some(secret) = item.secret.as_ref() {
                        let scope = secret
                            .scope
                            .as_ref()
                            .map(format_scope)
                            .unwrap_or_else(|| "unspecified".to_string());
                        println!(
                            "{} action={} secret={}/{} requested_by={} created_at={}",
                            item.request_id,
                            action,
                            scope,
                            secret.name,
                            item.requester_token_id,
                            item.created_at
                        );
                        if !item.reason.trim().is_empty() {
                            println!("  reason={}", item.reason);
                        }
                    } else {
                        println!("{} action={} (missing secret ref)", item.request_id, action);
                    }
                }
                print_kv("pending_count", pending_count);
            }
        }
        Commands::Approve {
            request_id,
            biometric,
            actor,
            message,
        } => {
            if biometric {
                confirm_biometric_approval(&mut client, request_id.as_str()).await?;
            } else {
                confirm_human_approval(request_id.as_str(), true)?;
            }
            let response = client
                .approve_access(ResolveApprovalRequest {
                    request_id,
                    actor,
                    message,
                })
                .await?
                .into_inner();
            if let Some(request) = response.request {
                print_kv("request_id", request.request_id);
                print_kv("state", approval_state_label(request.state));
                print_kv("action", request.action);
            }
            if response.approval_receipt.trim().is_empty() {
                print_kv("approval_receipt", "");
            } else {
                print_kv("approval_receipt", response.approval_receipt);
            }
        }
        Commands::Deny {
            request_id,
            actor,
            message,
        } => {
            confirm_human_approval(request_id.as_str(), false)?;
            let response = client
                .deny_access(ResolveApprovalRequest {
                    request_id,
                    actor,
                    message,
                })
                .await?
                .into_inner();
            if let Some(request) = response.request {
                print_kv("request_id", request.request_id);
                print_kv("state", approval_state_label(request.state));
                print_kv("action", request.action);
            }
        }
        Commands::Token { command } => match command {
            TokenCommands::IssueService {
                service_name,
                ttl_seconds,
                issued_by,
            } => {
                let response = client
                    .issue_service_token(IssueServiceTokenRequest {
                        service_name,
                        ttl_seconds: ttl_seconds.unwrap_or(0),
                        issued_by,
                    })
                    .await?
                    .into_inner();
                print_kv("token", response.token);
                if let Some(info) = response.info {
                    print_token_info(&info);
                }
            }
            TokenCommands::IssueAgent {
                identity_id,
                project,
                scopes,
                ttl_seconds,
                issued_by_service,
            } => {
                let response = client
                    .issue_agent_token(IssueAgentTokenRequest {
                        identity_id: identity_id.unwrap_or_default(),
                        project: project.unwrap_or_default(),
                        scopes: scopes
                            .into_iter()
                            .map(token_scope_arg_to_proto)
                            .collect::<Vec<i32>>(),
                        ttl_seconds: ttl_seconds.unwrap_or(0),
                        issued_by_service,
                    })
                    .await?
                    .into_inner();
                print_kv("token", response.token);
                if let Some(info) = response.info {
                    print_token_info(&info);
                }
            }
            TokenCommands::List {
                token_type,
                service_name,
                identity_id,
                limit,
            } => {
                let response = client
                    .list_active_tokens(ListActiveTokensRequest {
                        token_type: token_type
                            .map(token_type_arg_to_proto)
                            .unwrap_or(proto::TokenType::Unspecified as i32),
                        service_name: service_name.unwrap_or_default(),
                        identity_id: identity_id.unwrap_or_default(),
                        limit,
                    })
                    .await?
                    .into_inner();
                if response.tokens.is_empty() {
                    println!("no active tokens");
                } else {
                    let count = response.tokens.len();
                    for token in response.tokens {
                        let token_type = proto::TokenType::try_from(token.token_type)
                            .unwrap_or(proto::TokenType::Unspecified);
                        println!(
                            "{} type={} service={} identity={} project={} expires_at={}",
                            token.token_id,
                            format_token_type(token_type),
                            blank_dash(token.service_name.as_str()),
                            blank_dash(token.identity_id.as_str()),
                            blank_dash(token.project.as_str()),
                            token.expires_at
                        );
                    }
                    print_kv("active_count", count);
                }
            }
            TokenCommands::Revoke { token_id, actor } => {
                let response = client
                    .revoke_token(RevokeTokenRequest { token_id, actor })
                    .await?
                    .into_inner();
                print_kv("revoked", response.revoked);
            }
        },
        Commands::GrantAccess {
            secret,
            grantee_scope,
            grantee_id,
            actor,
        } => {
            let secret_ref = parse_secret_ref_or_global(secret.as_str())?;
            let grantee_scope = parse_scope_selector_value(grantee_scope.as_str())?;
            let response = client
                .grant_access(GrantAccessRequest {
                    secret: Some(secret_ref),
                    grantee_scope: Some(grantee_scope),
                    grantee_id,
                    actor,
                })
                .await?
                .into_inner();
            let secret = response.secret.ok_or("missing secret in grant response")?;
            let scope = secret
                .scope
                .as_ref()
                .map(format_scope)
                .unwrap_or_else(|| "unspecified".to_string());
            let grantee_scope = response
                .grantee_scope
                .as_ref()
                .map(format_scope)
                .unwrap_or_else(|| "unspecified".to_string());
            print_kv("secret", format!("{scope}/{}", secret.name));
            print_kv("grantee_scope", grantee_scope);
            print_kv("grantee_id", response.grantee_id);
            print_kv("created_at", response.created_at);
        }
        Commands::RevokeAccess {
            secret,
            grantee_scope,
            grantee_id,
            actor,
        } => {
            let secret_ref = parse_secret_ref_or_global(secret.as_str())?;
            let grantee_scope = parse_scope_selector_value(grantee_scope.as_str())?;
            let response = client
                .revoke_access(RevokeAccessRequest {
                    secret: Some(secret_ref),
                    grantee_scope: Some(grantee_scope),
                    grantee_id,
                    actor,
                })
                .await?
                .into_inner();
            print_kv("revoked", response.revoked);
        }
        Commands::ListGrants { secret } => {
            let secret_ref = parse_secret_ref_or_global(secret.as_str())?;
            let response = client
                .list_grants(ListGrantsRequest {
                    secret: Some(secret_ref),
                })
                .await?
                .into_inner();
            if response.grants.is_empty() {
                println!("no grants");
            } else {
                let count = response.grants.len();
                for grant in response.grants {
                    let secret = grant
                        .secret
                        .as_ref()
                        .ok_or("missing secret in grant item")?;
                    let secret_scope = secret
                        .scope
                        .as_ref()
                        .map(format_scope)
                        .unwrap_or_else(|| "unspecified".to_string());
                    let grantee_scope = grant
                        .grantee_scope
                        .as_ref()
                        .map(format_scope)
                        .unwrap_or_else(|| "unspecified".to_string());
                    println!(
                        "secret={}/{} grantee_scope={} grantee_id={} created_at={} created_by={}",
                        secret_scope,
                        secret.name,
                        grantee_scope,
                        grant.grantee_id,
                        grant.created_at,
                        blank_dash(grant.created_by.as_str())
                    );
                }
                print_kv("count", count);
            }
        }
        Commands::Audit {
            scope,
            since,
            until,
            limit,
        } => {
            let scope = scope
                .map(|value| parse_scope_selector_value(value.as_str()))
                .transpose()?;
            let response = client
                .get_audit_log(GetAuditLogRequest {
                    scope,
                    since: since.unwrap_or_default(),
                    until: until.unwrap_or_default(),
                    limit,
                })
                .await?
                .into_inner();
            if response.entries.is_empty() {
                println!("no audit entries");
            } else {
                let count = response.entries.len();
                for entry in response.entries {
                    let secret = entry
                        .secret
                        .as_ref()
                        .map(|secret| {
                            let scope = secret
                                .scope
                                .as_ref()
                                .map(format_scope)
                                .unwrap_or_else(|| "unspecified".to_string());
                            format!("{scope}/{}", secret.name)
                        })
                        .unwrap_or_else(|| "-".to_string());
                    println!(
                        "{} action={} actor={} secret={} result={} details={}",
                        entry.ts,
                        entry.action,
                        blank_dash(entry.actor.as_str()),
                        secret,
                        entry.result,
                        blank_dash(entry.details.as_str())
                    );
                }
                print_kv("count", count);
            }
        }
        Commands::Export { scope, output } => {
            let scope = scope
                .map(|value| parse_scope_selector_value(value.as_str()))
                .transpose()?;
            let response = client
                .export_secrets(ExportSecretsRequest { scope })
                .await?
                .into_inner();
            if response.encrypted_bundle.is_empty() {
                return Err("export returned empty bundle".into());
            }
            let output = match output {
                Some(path) => PathBuf::from(path),
                None => default_export_path(),
            };
            write_secure_bytes(output.as_path(), response.encrypted_bundle.as_slice())?;
            print_kv("exported", output.display());
            print_kv("bytes", response.encrypted_bundle.len());
        }
        Commands::Import {
            input,
            merge,
            actor,
        } => {
            let path = PathBuf::from(input);
            let bundle = fs::read(path.as_path())?;
            let response = client
                .import_secrets(ImportSecretsRequest {
                    encrypted_bundle: bundle,
                    merge,
                    actor,
                })
                .await?
                .into_inner();
            print_kv("imported_secret_count", response.imported_secret_count);
            print_kv("merge", merge);
        }
        Commands::Rotate { actor } => {
            let response = client
                .rotate_master_key(RotateMasterKeyRequest { actor })
                .await?
                .into_inner();
            print_kv("new_key_id", response.new_key_id);
            print_kv("rotated_secret_count", response.rotated_secret_count);
        }
        Commands::Examples { .. }
        | Commands::Usage
        | Commands::Cluster { .. }
        | Commands::Policy { .. }
        | Commands::Lease { .. } => {
            unreachable!("local command is handled before daemon connect")
        }
    }

    Ok(0)
}

async fn run_cluster_command(command: ClusterCommands) -> Result<i32, Box<dyn std::error::Error>> {
    match command {
        ClusterCommands::Init {
            node_id,
            listen,
            quorum,
            label,
            master_node_id,
            force,
        } => run_cluster_init(node_id, listen, quorum, label, master_node_id, force),
        ClusterCommands::Status => run_cluster_status(),
        ClusterCommands::Health => run_cluster_health(),
        ClusterCommands::Peers => run_cluster_peers(),
        ClusterCommands::Invite { ttl_seconds } => run_cluster_invite(ttl_seconds),
        ClusterCommands::Peer { command } => run_cluster_peer_command(command),
        ClusterCommands::Sync {
            once,
            dry_run,
            peer,
            limit,
        } => run_cluster_sync(once, dry_run, peer, limit).await,
        ClusterCommands::BootstrapLedger { peer, limit } => {
            run_cluster_bootstrap_ledger(peer, limit).await
        }
        ClusterCommands::Install {
            artifact_dir,
            prefix,
            data_dir,
            bind,
            supervisor,
            force,
        } => run_cluster_install(
            ClusterInstallMode::Install,
            artifact_dir,
            prefix,
            data_dir,
            bind,
            supervisor,
            force,
            None,
        ),
        ClusterCommands::Rebuild {
            artifact_dir,
            prefix,
            data_dir,
            bind,
            supervisor,
            backup_dir,
        } => run_cluster_install(
            ClusterInstallMode::Rebuild,
            artifact_dir,
            prefix,
            data_dir,
            bind,
            supervisor,
            true,
            Some(backup_dir),
        ),
        ClusterCommands::Migrate { dry_run } => run_cluster_migrate(dry_run),
        ClusterCommands::RewrapValues { dry_run, actor } => {
            run_cluster_rewrap_values(dry_run, actor)
        }
        ClusterCommands::Verify { repair } => run_cluster_verify(repair),
        ClusterCommands::Fork {
            parent_checkpoint,
            actor,
            reason,
        } => run_cluster_fork(parent_checkpoint, actor, reason),
        ClusterCommands::ReplayFork {
            fork_id,
            confirm_rewind,
            backup_confirmed,
            actor,
        } => run_cluster_replay_fork(fork_id, confirm_rewind, backup_confirmed, actor),
        ClusterCommands::Collisions => run_cluster_collisions(),
        ClusterCommands::ResolveCollision {
            collision_id,
            resolution,
            actor,
            allow_local,
        } => run_cluster_resolve_collision(collision_id, resolution, actor, allow_local).await,
        ClusterCommands::Join {
            invite,
            node_id,
            listen,
            label,
            force,
        } => run_cluster_join(invite, node_id, listen, label, force),
    }
}

fn run_cluster_invite(ttl_seconds: u64) -> Result<i32, Box<dyn std::error::Error>> {
    if ttl_seconds == 0 {
        return Err("invite ttl-seconds must be greater than 0".into());
    }
    let data_dir = resolve_primary_data_dir();
    let config = ClusterConfig::load(data_dir.join(CLUSTER_CONFIG_FILE).as_path())?;
    let identity = NodeIdentity::load(data_dir.join(NODE_IDENTITY_FILE).as_path())?;
    let invite = ClusterInvite::create(&config, &identity, ttl_seconds)?;
    let token = invite.encode()?;

    print_cluster_kv("invite_created", true);
    print_cluster_kv("cluster_id", config.cluster_id.as_str());
    print_cluster_kv("node_id", config.node_id.as_str());
    print_cluster_kv("endpoint", config.listen.as_str());
    if let Some(wrap_public_key) = identity.wrap_public_key_b64.as_ref() {
        print_cluster_kv("wrap_public_key", wrap_public_key.as_str());
    }
    print_cluster_kv("expires_at", invite.body.expires_at.to_rfc3339());
    print_cluster_kv("invite", token.as_str());
    Ok(0)
}

fn run_cluster_join(
    invite: String,
    node_id: Option<String>,
    listen: Option<String>,
    label: Option<String>,
    force: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    let invite = ClusterInvite::decode(invite.as_str())?;
    let node_id =
        normalize_optional_string(node_id.ok_or("cluster join requires --node-id for this node")?)
            .ok_or("cluster join --node-id must not be empty")?;
    let listen =
        normalize_optional_string(listen.ok_or("cluster join requires --listen for this node")?)
            .ok_or("cluster join --listen must not be empty")?;
    if node_id == invite.body.inviter_node_id {
        return Err("cluster join node_id must not match inviter node id".into());
    }

    let data_dir = resolve_primary_data_dir();
    let config_path = data_dir.join(CLUSTER_CONFIG_FILE);
    let identity_path = data_dir.join(NODE_IDENTITY_FILE);
    if !force && (config_path.exists() || identity_path.exists()) {
        return Err(format!(
            "cluster files already exist in {}; pass --force to replace cluster.toml and node-identity.json",
            data_dir.display()
        )
        .into());
    }

    fs::create_dir_all(data_dir.as_path())?;
    let config = ClusterConfig {
        enabled: true,
        cluster_id: invite.body.cluster_id.clone(),
        node_id: node_id.clone(),
        listen,
        quorum: invite.body.quorum,
        master_node_id: invite.body.master_node_id.clone(),
        peers: vec![invite.peer_config()],
    };
    let identity = NodeIdentity::generate(node_id.as_str(), label.unwrap_or_default().as_str())?;
    config.save(config_path.as_path())?;
    identity.save(identity_path.as_path())?;

    print_cluster_kv("cluster_joined", true);
    print_cluster_kv("data_dir", data_dir.display());
    print_cluster_kv("cluster_id", config.cluster_id.as_str());
    print_cluster_kv("node_id", config.node_id.as_str());
    print_cluster_kv("listen", config.listen.as_str());
    print_cluster_kv("peer_node_id", config.peers[0].node_id.as_str());
    print_cluster_kv("peer_endpoint", config.peers[0].endpoint.as_str());
    print_cluster_kv(
        "peer_wrap_public_key",
        config.peers[0].wrap_public_key.as_deref().unwrap_or(""),
    );
    Ok(0)
}

fn run_cluster_peer_command(
    command: ClusterPeerCommands,
) -> Result<i32, Box<dyn std::error::Error>> {
    let data_dir = resolve_primary_data_dir();
    let config_path = data_dir.join(CLUSTER_CONFIG_FILE);
    let mut config = ClusterConfig::load(config_path.as_path())?;

    match command {
        ClusterPeerCommands::Add {
            node_id,
            endpoint,
            public_key,
            wrap_public_key,
        } => {
            let peer = PeerConfig {
                node_id,
                endpoint,
                public_key,
                wrap_public_key,
            };
            peer.validate()?;
            if peer.node_id == config.node_id {
                return Err("peer node_id must not match local node_id".into());
            }
            if config.peers.iter().any(|item| item.node_id == peer.node_id) {
                return Err(format!("peer already exists: {}", peer.node_id).into());
            }
            config.peers.push(peer.clone());
            config.save(config_path.as_path())?;
            print_cluster_kv("peer_added", true);
            print_cluster_peer(&peer);
        }
        ClusterPeerCommands::Update {
            node_id,
            endpoint,
            public_key,
            wrap_public_key,
        } => {
            let Some(peer) = config.peers.iter_mut().find(|item| item.node_id == node_id) else {
                return Err(format!("peer not found: {node_id}").into());
            };
            if let Some(endpoint) = endpoint {
                peer.endpoint = endpoint;
            }
            if let Some(public_key) = public_key {
                peer.public_key = public_key;
            }
            if let Some(wrap_public_key) = wrap_public_key {
                peer.wrap_public_key = Some(wrap_public_key);
            }
            peer.validate()?;
            let updated = peer.clone();
            config.save(config_path.as_path())?;
            print_cluster_kv("peer_updated", true);
            print_cluster_peer(&updated);
        }
        ClusterPeerCommands::Remove { node_id } => {
            let before = config.peers.len();
            config.peers.retain(|peer| peer.node_id != node_id);
            if config.peers.len() == before {
                return Err(format!("peer not found: {node_id}").into());
            }
            config.save(config_path.as_path())?;
            print_cluster_kv("peer_removed", true);
            print_cluster_kv("peer_node_id", node_id.as_str());
        }
    }
    Ok(0)
}

async fn run_cluster_sync(
    once: bool,
    dry_run: bool,
    peer_filter: Option<String>,
    limit: u32,
) -> Result<i32, Box<dyn std::error::Error>> {
    if !once {
        return Err("cluster sync currently supports only --once".into());
    }
    if limit == 0 {
        return Err("cluster sync --limit must be greater than 0".into());
    }

    let data_dir = resolve_primary_data_dir();
    let config = ClusterConfig::load(data_dir.join(CLUSTER_CONFIG_FILE).as_path())?;
    let identity = NodeIdentity::load(data_dir.join(NODE_IDENTITY_FILE).as_path())?;
    if identity.node_id != config.node_id {
        return Err(format!(
            "node identity mismatch: config node_id={} identity node_id={}",
            config.node_id, identity.node_id
        )
        .into());
    }
    let ledger = LedgerStore::open(data_dir.as_path())?;
    let peers: Vec<PeerConfig> = config
        .peers
        .iter()
        .filter(|peer| {
            peer_filter
                .as_ref()
                .map(|filter| filter == &peer.node_id)
                .unwrap_or(true)
        })
        .cloned()
        .collect();
    if peer_filter.is_some() && peers.is_empty() {
        return Err("cluster sync peer filter matched no configured peers".into());
    }

    print_cluster_kv("sync_once", true);
    print_cluster_kv("sync_dry_run", dry_run);
    print_cluster_kv("sync_peers", peers.len());

    for peer in peers {
        let report = sync_peer_once(&config, &identity, &ledger, &peer, dry_run, limit).await?;
        print_cluster_kv("peer_node_id", peer.node_id.as_str());
        print_cluster_kv("peer_endpoint", peer.endpoint.as_str());
        print_cluster_kv("peer_accepted", report.accepted);
        print_cluster_kv("peer_latest_position", report.peer_latest_position);
        print_cluster_kv("pulled_operations", report.pulled_operations);
        print_cluster_kv("duplicate_operations", report.duplicate_operations);
        print_cluster_kv("materialized_records", report.materialized_records);
        print_cluster_kv("pushed_operations", report.pushed_operations);
        print_cluster_kv("local_latest_position", report.local_latest_position);
    }
    Ok(0)
}

async fn run_cluster_bootstrap_ledger(
    peer_filter: Option<String>,
    limit: u32,
) -> Result<i32, Box<dyn std::error::Error>> {
    if limit == 0 {
        return Err("cluster bootstrap-ledger --limit must be greater than 0".into());
    }

    let data_dir = resolve_primary_data_dir();
    let config = ClusterConfig::load(data_dir.join(CLUSTER_CONFIG_FILE).as_path())?;
    let identity = NodeIdentity::load(data_dir.join(NODE_IDENTITY_FILE).as_path())?;
    if identity.node_id != config.node_id {
        return Err(format!(
            "node identity mismatch: config node_id={} identity node_id={}",
            config.node_id, identity.node_id
        )
        .into());
    }
    let ledger = LedgerStore::open(data_dir.as_path())?;
    let peers: Vec<PeerConfig> = config
        .peers
        .iter()
        .filter(|peer| {
            peer_filter
                .as_ref()
                .map(|filter| filter == &peer.node_id)
                .unwrap_or(true)
        })
        .cloned()
        .collect();
    if peer_filter.is_some() && peers.is_empty() {
        return Err("cluster bootstrap-ledger peer filter matched no configured peers".into());
    }

    print_cluster_kv("bootstrap_ledger", true);
    print_cluster_kv("bootstrap_peers", peers.len());
    for peer in peers {
        let report = bootstrap_peer_ledger(&config, &identity, &ledger, &peer, limit).await?;
        print_cluster_kv("peer_node_id", peer.node_id.as_str());
        print_cluster_kv("peer_endpoint", peer.endpoint.as_str());
        print_cluster_kv("peer_accepted", report.accepted);
        print_cluster_kv("peer_latest_position", report.peer_latest_position);
        print_cluster_kv("pulled_operations", report.pulled_operations);
        print_cluster_kv("duplicate_operations", report.duplicate_operations);
        print_cluster_kv("materialized_records", report.materialized_records);
        print_cluster_kv("local_latest_position", report.local_latest_position);
    }
    Ok(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClusterInstallMode {
    Install,
    Rebuild,
}

impl ClusterInstallMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Rebuild => "rebuild",
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_cluster_install(
    mode: ClusterInstallMode,
    artifact_dir: String,
    prefix: String,
    data_dir: String,
    bind: String,
    supervisor: ClusterSupervisorKind,
    force: bool,
    backup_dir: Option<String>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let artifact_dir = PathBuf::from(artifact_dir);
    let prefix = PathBuf::from(prefix);
    let data_dir = PathBuf::from(data_dir);
    let bin_dir = prefix.join("bin");
    let etc_dir = prefix.join("etc/hem");
    let supervisor_dir = prefix.join("supervisor");
    let env_file = etc_dir.join("hemd.env");
    let manifest_path = etc_dir.join("install-manifest.json");
    let supervisor_file = supervisor_file_path(supervisor, supervisor_dir.as_path());
    let backup_dir = match (mode, backup_dir) {
        (ClusterInstallMode::Rebuild, Some(path)) => Some(PathBuf::from(path)),
        (ClusterInstallMode::Rebuild, None) => {
            return Err("cluster rebuild requires --backup-dir".into());
        }
        (ClusterInstallMode::Install, Some(path)) => Some(PathBuf::from(path)),
        (ClusterInstallMode::Install, None) => None,
    };

    if !artifact_dir.is_dir() {
        return Err(format!("artifact dir does not exist: {}", artifact_dir.display()).into());
    }
    fs::create_dir_all(bin_dir.as_path())?;
    fs::create_dir_all(etc_dir.as_path())?;
    fs::create_dir_all(data_dir.as_path())?;
    if supervisor != ClusterSupervisorKind::None {
        fs::create_dir_all(supervisor_dir.as_path())?;
    }
    if let Some(backup_dir) = backup_dir.as_ref() {
        fs::create_dir_all(backup_dir.as_path())?;
        backup_file_if_exists(
            bin_dir.join("hem").as_path(),
            backup_dir.join("hem").as_path(),
        )?;
        backup_file_if_exists(
            bin_dir.join("hemd").as_path(),
            backup_dir.join("hemd").as_path(),
        )?;
        backup_file_if_exists(env_file.as_path(), backup_dir.join("hemd.env").as_path())?;
        if let Some(supervisor_file) = supervisor_file.as_ref() {
            let backup_name = supervisor_file
                .file_name()
                .ok_or("supervisor file has no file name")?;
            backup_file_if_exists(
                supervisor_file.as_path(),
                backup_dir.join(backup_name).as_path(),
            )?;
        }
        backup_file_if_exists(
            manifest_path.as_path(),
            backup_dir.join("install-manifest.json").as_path(),
        )?;
    }

    let overwrite = force || mode == ClusterInstallMode::Rebuild;
    let hem_bin =
        install_artifact_binary(artifact_dir.as_path(), bin_dir.as_path(), "hem", overwrite)?;
    let hemd_bin =
        install_artifact_binary(artifact_dir.as_path(), bin_dir.as_path(), "hemd", overwrite)?;
    let endpoint = format!("http://{bind}");
    let env_body = render_hemd_env(data_dir.as_path(), endpoint.as_str());
    write_checked(env_file.as_path(), env_body.as_bytes(), overwrite)?;
    if let Some(supervisor_file) = supervisor_file.as_ref() {
        let body = render_supervisor_file(
            supervisor,
            hemd_bin.as_path(),
            data_dir.as_path(),
            bind.as_str(),
            env_file.as_path(),
        )?;
        write_checked(supervisor_file.as_path(), body.as_bytes(), overwrite)?;
    }

    let manifest = serde_json::json!({
        "mode": mode.as_str(),
        "installed_at": Utc::now().to_rfc3339(),
        "artifact_dir": artifact_dir.display().to_string(),
        "prefix": prefix.display().to_string(),
        "data_dir": data_dir.display().to_string(),
        "bind": bind.as_str(),
        "endpoint": endpoint.as_str(),
        "hem_bin": hem_bin.display().to_string(),
        "hemd_bin": hemd_bin.display().to_string(),
        "env_file": env_file.display().to_string(),
        "supervisor_kind": supervisor.as_str(),
        "supervisor_file": supervisor_file
            .as_ref()
            .map(|path| path.display().to_string()),
        "backup_dir": backup_dir
            .as_ref()
            .map(|path| path.display().to_string()),
        "package_version": env!("CARGO_PKG_VERSION"),
    });
    let manifest_body = serde_json::to_vec_pretty(&manifest)?;
    write_checked(manifest_path.as_path(), manifest_body.as_slice(), overwrite)?;

    print_cluster_kv("cluster_installed", true);
    print_cluster_kv("install_mode", mode.as_str());
    print_cluster_kv("artifact_dir", artifact_dir.display());
    print_cluster_kv("install_prefix", prefix.display());
    print_cluster_kv("hem_bin", hem_bin.display());
    print_cluster_kv("hemd_bin", hemd_bin.display());
    print_cluster_kv("data_dir", data_dir.display());
    print_cluster_kv("bind", bind.as_str());
    print_cluster_kv("endpoint", endpoint.as_str());
    print_cluster_kv("env_file", env_file.display());
    print_cluster_kv("supervisor_kind", supervisor.as_str());
    if let Some(supervisor_file) = supervisor_file.as_ref() {
        print_cluster_kv("supervisor_file", supervisor_file.display());
    }
    if let Some(backup_dir) = backup_dir.as_ref() {
        print_cluster_kv("backup_dir", backup_dir.display());
    }
    print_cluster_kv("install_manifest", manifest_path.display());
    print_cluster_kv(
        "verify_version_command",
        format!("{} --version", hem_bin.display()),
    );
    print_cluster_kv(
        "verify_health_command",
        format!("{} --endpoint {} health", hem_bin.display(), endpoint),
    );
    print_cluster_kv(
        "verify_cluster_status_command",
        format!(
            "HEM_DATA_DIR={} {} cluster status",
            data_dir.display(),
            hem_bin.display()
        ),
    );
    print_cluster_kv(
        "verify_ledger_command",
        format!(
            "HEM_DATA_DIR={} {} cluster verify",
            data_dir.display(),
            hem_bin.display()
        ),
    );
    Ok(0)
}

fn supervisor_file_path(
    supervisor: ClusterSupervisorKind,
    supervisor_dir: &Path,
) -> Option<PathBuf> {
    match supervisor {
        ClusterSupervisorKind::Launchd => Some(supervisor_dir.join("io.valhall.hemd.plist")),
        ClusterSupervisorKind::Systemd => Some(supervisor_dir.join("hemd.service")),
        ClusterSupervisorKind::None => None,
    }
}

fn install_artifact_binary(
    artifact_dir: &Path,
    bin_dir: &Path,
    name: &str,
    overwrite: bool,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let source = artifact_dir.join(name);
    if !source.is_file() {
        return Err(format!("release artifact is missing binary: {}", source.display()).into());
    }
    let destination = bin_dir.join(name);
    if destination.exists() && !overwrite {
        return Err(format!(
            "install target already exists: {}; pass --force or use cluster rebuild",
            destination.display()
        )
        .into());
    }
    fs::copy(source.as_path(), destination.as_path())?;
    set_executable_permissions(destination.as_path())?;
    Ok(destination)
}

fn backup_file_if_exists(
    source: &Path,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if source.exists() {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(source, destination)?;
    }
    Ok(())
}

fn write_checked(
    path: &Path,
    bytes: &[u8],
    overwrite: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() && !overwrite {
        return Err(format!(
            "install target already exists: {}; pass --force or use cluster rebuild",
            path.display()
        )
        .into());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

fn set_executable_permissions(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn render_hemd_env(data_dir: &Path, endpoint: &str) -> String {
    format!(
        "HEM_DATA_DIR={}\nVALHALL_HEMD_ENDPOINT={endpoint}\n",
        data_dir.display()
    )
}

fn render_supervisor_file(
    supervisor: ClusterSupervisorKind,
    hemd_bin: &Path,
    data_dir: &Path,
    bind: &str,
    env_file: &Path,
) -> Result<String, Box<dyn std::error::Error>> {
    match supervisor {
        ClusterSupervisorKind::Launchd => Ok(render_launchd_plist(hemd_bin, data_dir, bind)),
        ClusterSupervisorKind::Systemd => {
            Ok(render_systemd_unit(hemd_bin, data_dir, bind, env_file))
        }
        ClusterSupervisorKind::None => Err("supervisor file requested for supervisor=none".into()),
    }
}

fn render_launchd_plist(hemd_bin: &Path, data_dir: &Path, bind: &str) -> String {
    let hemd_bin = xml_escape(hemd_bin.to_string_lossy().as_ref());
    let data_dir = xml_escape(data_dir.to_string_lossy().as_ref());
    let bind = xml_escape(bind);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.valhall.hemd</string>
  <key>ProgramArguments</key>
  <array>
    <string>{hemd_bin}</string>
    <string>--bind</string>
    <string>{bind}</string>
    <string>--data-dir</string>
    <string>{data_dir}</string>
  </array>
  <key>KeepAlive</key>
  <true/>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{data_dir}/hemd.out.log</string>
  <key>StandardErrorPath</key>
  <string>{data_dir}/hemd.err.log</string>
</dict>
</plist>
"#
    )
}

fn render_systemd_unit(hemd_bin: &Path, data_dir: &Path, bind: &str, env_file: &Path) -> String {
    format!(
        "[Unit]\nDescription=Valhall Hem daemon\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nEnvironmentFile={}\nExecStart={} --bind {} --data-dir {}\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n",
        env_file.display(),
        hemd_bin.display(),
        bind,
        data_dir.display()
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[derive(Debug)]
struct ClusterPeerSyncReport {
    accepted: bool,
    peer_latest_position: i64,
    pulled_operations: usize,
    duplicate_operations: usize,
    materialized_records: usize,
    pushed_operations: u32,
    local_latest_position: i64,
}

async fn bootstrap_peer_ledger(
    config: &ClusterConfig,
    identity: &NodeIdentity,
    ledger: &LedgerStore,
    peer: &PeerConfig,
    limit: u32,
) -> Result<ClusterPeerSyncReport, Box<dyn std::error::Error>> {
    let mut client = connect_client(peer.endpoint.as_str(), None).await?;
    let hello = client
        .peer_hello(signed_peer_transport_request(
            PeerHelloRequest {
                cluster_id: config.cluster_id.clone(),
                node_id: config.node_id.clone(),
                public_key: identity.signing_public_key_b64.clone(),
            },
            identity,
            config.cluster_id.as_str(),
            PEER_METHOD_HELLO,
        )?)
        .await?
        .into_inner();
    if hello.node_id != peer.node_id {
        return Err(format!(
            "peer hello node_id mismatch expected={} actual={}",
            peer.node_id, hello.node_id
        )
        .into());
    }
    if hello.cluster_id != config.cluster_id {
        return Err(format!(
            "peer hello cluster_id mismatch expected={} actual={}",
            config.cluster_id, hello.cluster_id
        )
        .into());
    }

    let mut pulled_operations = 0_usize;
    let mut duplicate_operations = 0_usize;
    let mut materialized_records = 0_usize;
    loop {
        let after_position = ledger.latest_position()?;
        let remote = client
            .peer_list_operations(signed_peer_transport_request(
                PeerListOperationsRequest {
                    after_position,
                    limit,
                    peer_node_id: String::new(),
                    use_recorded_cursor: false,
                },
                identity,
                config.cluster_id.as_str(),
                PEER_METHOD_LIST_OPERATIONS,
            )?)
            .await?
            .into_inner();
        if remote.operations.is_empty() {
            return Ok(ClusterPeerSyncReport {
                accepted: hello.accepted,
                peer_latest_position: remote.latest_position,
                pulled_operations,
                duplicate_operations,
                materialized_records,
                pushed_operations: 0,
                local_latest_position: ledger.latest_position()?,
            });
        }

        let envelopes = remote
            .operations
            .iter()
            .cloned()
            .map(core_envelope_from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        let imported =
            ledger.bootstrap_from_peer_operations(config.cluster_id.as_str(), &envelopes)?;
        pulled_operations += remote.operations.len();
        duplicate_operations += imported.duplicate_operations;
        materialized_records += imported.materialized_records;
        if let Some(last) = remote.operations.last() {
            client
                .peer_ack_operations(signed_peer_transport_request(
                    PeerAckOperationsRequest {
                        peer_node_id: config.node_id.clone(),
                        position: last.position,
                        body_hash_b64: last.body_hash_b64.clone(),
                    },
                    identity,
                    config.cluster_id.as_str(),
                    PEER_METHOD_ACK_OPERATIONS,
                )?)
                .await?;
        }
        if remote.operations.len() < limit as usize
            || imported.latest_position >= remote.latest_position
        {
            return Ok(ClusterPeerSyncReport {
                accepted: hello.accepted,
                peer_latest_position: remote.latest_position,
                pulled_operations,
                duplicate_operations,
                materialized_records,
                pushed_operations: 0,
                local_latest_position: imported.latest_position,
            });
        }
    }
}

async fn sync_peer_once(
    config: &ClusterConfig,
    identity: &NodeIdentity,
    ledger: &LedgerStore,
    peer: &PeerConfig,
    dry_run: bool,
    limit: u32,
) -> Result<ClusterPeerSyncReport, Box<dyn std::error::Error>> {
    let mut client = connect_client(peer.endpoint.as_str(), None).await?;
    let hello = client
        .peer_hello(signed_peer_transport_request(
            PeerHelloRequest {
                cluster_id: config.cluster_id.clone(),
                node_id: config.node_id.clone(),
                public_key: identity.signing_public_key_b64.clone(),
            },
            identity,
            config.cluster_id.as_str(),
            PEER_METHOD_HELLO,
        )?)
        .await?
        .into_inner();
    if hello.node_id != peer.node_id {
        return Err(format!(
            "peer hello node_id mismatch expected={} actual={}",
            peer.node_id, hello.node_id
        )
        .into());
    }
    if hello.cluster_id != config.cluster_id {
        return Err(format!(
            "peer hello cluster_id mismatch expected={} actual={}",
            config.cluster_id, hello.cluster_id
        )
        .into());
    }

    let remote = client
        .peer_list_operations(signed_peer_transport_request(
            PeerListOperationsRequest {
                after_position: 0,
                limit,
                peer_node_id: config.node_id.clone(),
                use_recorded_cursor: true,
            },
            identity,
            config.cluster_id.as_str(),
            PEER_METHOD_LIST_OPERATIONS,
        )?)
        .await?
        .into_inner();
    let pulled_operations = remote.operations.len();
    let mut duplicate_operations = 0_usize;
    let mut materialized_records = 0_usize;
    if !dry_run && !remote.operations.is_empty() {
        let envelopes = remote
            .operations
            .iter()
            .cloned()
            .map(core_envelope_from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        let bootstrap =
            ledger.bootstrap_from_peer_operations(config.cluster_id.as_str(), &envelopes)?;
        duplicate_operations = bootstrap.duplicate_operations;
        materialized_records = bootstrap.materialized_records;
        if let Some(last) = remote.operations.last() {
            client
                .peer_ack_operations(signed_peer_transport_request(
                    PeerAckOperationsRequest {
                        peer_node_id: config.node_id.clone(),
                        position: last.position,
                        body_hash_b64: last.body_hash_b64.clone(),
                    },
                    identity,
                    config.cluster_id.as_str(),
                    PEER_METHOD_ACK_OPERATIONS,
                )?)
                .await?;
        }
    }

    let peer_cursor = ledger
        .get_peer_cursor(peer.node_id.as_str())?
        .map(|cursor| cursor.last_position)
        .unwrap_or(0);
    let local_batch = ledger.list_after(peer_cursor, limit as usize)?;
    let pushed_operations = if dry_run || local_batch.is_empty() {
        0
    } else {
        let last_sent = local_batch.last().cloned();
        let pushed = client
            .peer_push_operations(signed_peer_transport_request(
                PeerPushOperationsRequest {
                    operations: local_batch
                        .iter()
                        .map(proto_envelope_from_operation)
                        .collect(),
                },
                identity,
                config.cluster_id.as_str(),
                PEER_METHOD_PUSH_OPERATIONS,
            )?)
            .await?
            .into_inner();
        if let Some(last_sent) = last_sent {
            ledger.record_peer_cursor(
                peer.node_id.as_str(),
                last_sent.position,
                last_sent.body_hash_b64.as_str(),
            )?;
        }
        pushed.accepted_count
    };

    Ok(ClusterPeerSyncReport {
        accepted: hello.accepted,
        peer_latest_position: hello.latest_position,
        pulled_operations,
        duplicate_operations,
        materialized_records,
        pushed_operations,
        local_latest_position: ledger.latest_position()?,
    })
}

fn run_cluster_migrate(dry_run: bool) -> Result<i32, Box<dyn std::error::Error>> {
    let data_dir = resolve_primary_data_dir();
    let config_path = data_dir.join(CLUSTER_CONFIG_FILE);
    let identity_path = data_dir.join(NODE_IDENTITY_FILE);
    let config = ClusterConfig::load(config_path.as_path())?;
    let identity = NodeIdentity::load(identity_path.as_path())?;
    if identity.node_id != config.node_id {
        return Err(format!(
            "node identity mismatch: config node_id={} identity node_id={}",
            config.node_id, identity.node_id
        )
        .into());
    }

    let store = HemStore::open(data_dir.as_path())?;
    let report = store.migrate_local_store_to_ledger(LocalStoreLedgerMigrationInput {
        cluster_id: config.cluster_id.as_str(),
        identity: &identity,
        dry_run,
    })?;

    print_cluster_kv("migration_dry_run", report.dry_run);
    print_cluster_kv("cluster_id", report.cluster_id.as_str());
    print_cluster_kv("node_id", report.node_id.as_str());
    print_cluster_kv("ledger_start_position", report.ledger_start_position);
    print_cluster_kv("ledger_end_position", report.ledger_end_position);
    print_cluster_kv("groups_scanned", report.groups_scanned);
    print_cluster_kv("secrets_scanned", report.secrets_scanned);
    print_cluster_kv("value_keys_scanned", report.value_keys_scanned);
    print_cluster_kv("grants_scanned", report.grants_scanned);
    print_cluster_kv("group_operations", report.group_operations);
    print_cluster_kv("metadata_operations", report.metadata_operations);
    print_cluster_kv("value_operations", report.value_operations);
    print_cluster_kv("grant_operations", report.grant_operations);
    print_cluster_kv("operations_planned", report.operations_planned);
    print_cluster_kv("operations_appended", report.operations_appended);
    print_cluster_kv("unsupported_records", report.unsupported_records.len());
    for record in report.unsupported_records {
        print_cluster_kv("unsupported_record", record);
    }
    Ok(0)
}

fn run_cluster_rewrap_values(
    dry_run: bool,
    actor: String,
) -> Result<i32, Box<dyn std::error::Error>> {
    let data_dir = resolve_primary_data_dir();
    let config_path = data_dir.join(CLUSTER_CONFIG_FILE);
    let identity_path = data_dir.join(NODE_IDENTITY_FILE);
    let config = ClusterConfig::load(config_path.as_path())?;
    let identity = NodeIdentity::load(identity_path.as_path())?;
    if identity.node_id != config.node_id {
        return Err(format!(
            "node identity mismatch: config node_id={} identity node_id={}",
            config.node_id, identity.node_id
        )
        .into());
    }
    let recipients = cluster_key_recipients(&config, &identity)?;
    let store = HemStore::open(data_dir.as_path())?;
    let report = store.rewrap_latest_ledger_values_for_nodes(LedgerValueRewrapInput {
        cluster_id: config.cluster_id.as_str(),
        identity: &identity,
        actor: actor.as_str(),
        recipients: recipients.as_slice(),
        dry_run,
    })?;

    print_cluster_kv("rewrap_dry_run", report.dry_run);
    print_cluster_kv("cluster_id", report.cluster_id.as_str());
    print_cluster_kv("node_id", report.node_id.as_str());
    print_cluster_kv("ledger_start_position", report.ledger_start_position);
    print_cluster_kv("ledger_end_position", report.ledger_end_position);
    print_cluster_kv("recipients", recipients.len());
    print_cluster_kv("values_scanned", report.values_scanned);
    print_cluster_kv("values_rewrapped", report.values_rewrapped);
    print_cluster_kv("values_already_current", report.values_already_current);
    print_cluster_kv("operations_planned", report.operations_planned);
    print_cluster_kv("operations_appended", report.operations_appended);
    print_cluster_kv("unsupported_records", report.unsupported_records.len());
    for record in report.unsupported_records {
        print_cluster_kv("unsupported_record", record);
    }
    Ok(0)
}

fn cluster_key_recipients(
    config: &ClusterConfig,
    identity: &NodeIdentity,
) -> Result<Vec<NodeKeyRecipient>, Box<dyn std::error::Error>> {
    let mut recipients = Vec::new();
    if let Some(public_key_b64) = identity.wrap_public_key_b64.as_ref() {
        recipients.push(NodeKeyRecipient {
            node_id: identity.node_id.clone(),
            public_key_b64: public_key_b64.clone(),
        });
    }
    for peer in &config.peers {
        if let Some(public_key_b64) = peer.wrap_public_key.as_ref() {
            recipients.push(NodeKeyRecipient {
                node_id: peer.node_id.clone(),
                public_key_b64: public_key_b64.clone(),
            });
        }
    }
    if recipients.is_empty() {
        return Err("cluster has no node wrap recipients configured".into());
    }
    Ok(recipients)
}

fn run_cluster_verify(repair: bool) -> Result<i32, Box<dyn std::error::Error>> {
    let data_dir = resolve_primary_data_dir();
    let ledger = LedgerStore::open(data_dir.as_path())?;
    let repaired_records = if repair {
        ledger.repair_materializers()?
    } else {
        0
    };
    let report = ledger.verify_integrity()?;
    let ledger_ok = report.ok;
    let security_report = inspect_data_dir_security(data_dir.as_path())?;
    let security_ok = security_report.ok;

    print_cluster_kv("ledger_ok", ledger_ok);
    print_cluster_kv("latest_position", report.latest_position);
    print_cluster_kv("latest_body_hash", report.latest_body_hash_b64.as_str());
    print_cluster_kv("operations_checked", report.operations_checked);
    print_cluster_kv("value_blobs_checked", report.value_blobs_checked);
    print_cluster_kv("checkpoints_checked", report.checkpoints_checked);
    print_cluster_kv(
        "checkpoint_cosignatures_checked",
        report.checkpoint_cosignatures_checked,
    );
    print_cluster_kv("peer_cursors_checked", report.peer_cursors_checked);
    print_cluster_kv("forks_declared", report.forks_declared);
    print_cluster_kv("fork_replays_declared", report.fork_replays_declared);
    print_cluster_kv("issues", report.issues.len());
    print_cluster_kv("repaired_materializer_records", repaired_records);
    print_cluster_kv("data_dir_security_ok", security_ok);
    print_cluster_kv("data_dir_security_issues", security_report.issues.len());
    for issue in report.issues {
        println!(
            "issue severity={} category={} reference={} message={}",
            issue.severity, issue.category, issue.reference, issue.message
        );
    }
    for issue in &security_report.issues {
        println!(
            "security_issue kind={} mode={} path={} message={}",
            issue.kind,
            format_mode(issue.mode),
            issue.path.display(),
            issue.message
        );
    }
    if !security_ok {
        append_cluster_security_audit(data_dir.as_path(), security_report.issues.len());
    }
    Ok(if ledger_ok && security_ok { 0 } else { 2 })
}

fn append_cluster_security_audit(data_dir: &Path, issue_count: usize) {
    let audit_store = match hem_core::AuditStore::open(data_dir) {
        Ok(store) => store,
        Err(err) => {
            eprintln!(
                "warning: failed to open audit store for cluster verify security audit: {err}"
            );
            return;
        }
    };
    let entry = CoreAuditEntry {
        audit_id: valhall_config::ids::generate_prefixed_entropy_id("aud"),
        ts: Utc::now(),
        action: "cluster.verify.security".to_string(),
        actor: "hem-cli".to_string(),
        token_id: String::new(),
        secret_scope: None,
        secret_name: String::new(),
        result: "unsafe_permissions".to_string(),
        details: format!("issues={issue_count}"),
    };
    if let Err(err) = audit_store.append(&entry) {
        eprintln!("warning: failed to append cluster verify security audit entry: {err}");
    }
}

fn format_mode(mode: Option<u32>) -> String {
    match mode {
        Some(mode) => format!("{mode:03o}"),
        None => "unknown".to_string(),
    }
}

fn run_cluster_fork(
    parent_checkpoint: Option<String>,
    actor: String,
    reason: String,
) -> Result<i32, Box<dyn std::error::Error>> {
    let actor = actor.trim();
    if actor.is_empty() {
        return Err("actor must not be empty".into());
    }
    let reason = reason.trim();
    if reason.is_empty() {
        return Err("fork reason must not be empty".into());
    }

    let data_dir = resolve_primary_data_dir();
    let config = ClusterConfig::load(data_dir.join(CLUSTER_CONFIG_FILE).as_path())?;
    let identity = NodeIdentity::load(data_dir.join(NODE_IDENTITY_FILE).as_path())?;
    if identity.node_id != config.node_id {
        return Err(format!(
            "node identity mismatch: config node_id={} identity node_id={}",
            config.node_id, identity.node_id
        )
        .into());
    }

    let ledger = LedgerStore::open(data_dir.as_path())?;
    let fork = ledger.declare_hard_fork(
        &identity,
        config.cluster_id.as_str(),
        parent_checkpoint.as_deref(),
        actor,
        reason,
    )?;

    print_cluster_kv("fork_declared", true);
    print_cluster_kv("fork_id", fork.fork_id.as_str());
    print_cluster_kv("epoch", fork.epoch);
    print_cluster_kv("parent_checkpoint_id", fork.parent_checkpoint_id.as_str());
    print_cluster_kv(
        "parent_checkpoint_hash",
        fork.parent_checkpoint_body_hash_b64.as_str(),
    );
    print_cluster_kv("parent_position", fork.parent_position);
    print_cluster_kv("operation_id", fork.operation_id.as_str());
    Ok(0)
}

fn run_cluster_replay_fork(
    fork_id: String,
    confirm_rewind: Option<String>,
    backup_confirmed: Option<String>,
    actor: String,
) -> Result<i32, Box<dyn std::error::Error>> {
    let fork_id = fork_id.trim();
    if fork_id.is_empty() {
        return Err("fork id must not be empty".into());
    }
    let actor = actor.trim();
    if actor.is_empty() {
        return Err("actor must not be empty".into());
    }
    let Some(confirm_rewind) = confirm_rewind else {
        return Err(format!("destructive replay requires --confirm-rewind {fork_id}").into());
    };
    if confirm_rewind.trim() != fork_id {
        return Err(format!("--confirm-rewind must exactly match fork id {fork_id}").into());
    }
    let Some(backup_reference) = backup_confirmed else {
        return Err("destructive replay requires --backup-confirmed <backup-reference>".into());
    };
    let backup_reference = backup_reference.trim();
    if backup_reference.is_empty() {
        return Err("--backup-confirmed must not be empty".into());
    }

    let data_dir = resolve_primary_data_dir();
    let config = ClusterConfig::load(data_dir.join(CLUSTER_CONFIG_FILE).as_path())?;
    let identity = NodeIdentity::load(data_dir.join(NODE_IDENTITY_FILE).as_path())?;
    if identity.node_id != config.node_id {
        return Err(format!(
            "node identity mismatch: config node_id={} identity node_id={}",
            config.node_id, identity.node_id
        )
        .into());
    }

    let ledger = LedgerStore::open(data_dir.as_path())?;
    let report = ledger.execute_hard_fork_replay(
        &identity,
        LedgerForkReplayInput {
            fork_id,
            actor,
            backup_reference,
        },
    )?;

    print_cluster_kv("fork_replay_executed", true);
    print_cluster_kv("replay_id", report.replay_id.as_str());
    print_cluster_kv("fork_id", report.fork_id.as_str());
    print_cluster_kv("parent_position", report.parent_position);
    print_cluster_kv("fork_position", report.fork_position);
    print_cluster_kv("latest_position", report.latest_position);
    print_cluster_kv("replay_operation_id", report.replay_operation_id.as_str());
    print_cluster_kv("operations_replayed", report.operations_replayed);
    print_cluster_kv("operations_skipped", report.operations_skipped);
    print_cluster_kv(
        "materializer_records_rebuilt",
        report.materializer_records_rebuilt,
    );
    Ok(0)
}

fn run_cluster_collisions() -> Result<i32, Box<dyn std::error::Error>> {
    let data_dir = resolve_primary_data_dir();
    let config_path = data_dir.join(CLUSTER_CONFIG_FILE);
    if !config_path.exists() {
        print_cluster_kv("collisions", 0);
        return Ok(0);
    }

    let config = ClusterConfig::load(config_path.as_path())?;
    let ledger = LedgerStore::open(data_dir.as_path())?;
    ledger.materialize_secret_value_versions()?;
    let collisions = ledger.list_open_collisions(config.cluster_id.as_str())?;
    print_cluster_kv("collisions", collisions.len());
    for collision in collisions {
        print_cluster_collision(&collision);
    }
    Ok(0)
}

async fn run_cluster_resolve_collision(
    collision_id: String,
    resolution: String,
    actor: String,
    allow_local: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    let collision_id = collision_id.trim();
    if collision_id.is_empty() {
        return Err("collision id must not be empty".into());
    }
    let resolution = resolution.trim();
    if resolution.is_empty() {
        return Err("resolution must not be empty".into());
    }
    let actor = actor.trim();
    if actor.is_empty() {
        return Err("actor must not be empty".into());
    }

    let data_dir = resolve_primary_data_dir();
    let config_path = data_dir.join(CLUSTER_CONFIG_FILE);
    let identity_path = data_dir.join(NODE_IDENTITY_FILE);
    let config = ClusterConfig::load(config_path.as_path())?;
    let identity = NodeIdentity::load(identity_path.as_path())?;
    if identity.node_id != config.node_id {
        return Err(format!(
            "node identity mismatch: config node_id={} identity node_id={}",
            config.node_id, identity.node_id
        )
        .into());
    }

    let ledger = LedgerStore::open(data_dir.as_path())?;
    ledger.materialize_secret_value_versions()?;
    let collision = ledger
        .get_collision(collision_id)?
        .ok_or_else(|| format!("open collision not found: {collision_id}"))?;
    if collision.state != "open" {
        return Err(format!("open collision not found: {collision_id}").into());
    }
    let agreement = if config.quorum > 1 && !allow_local {
        Some(
            collect_collision_quorum_agreement(&config, &identity, &ledger, &collision, resolution)
                .await?,
        )
    } else if config.quorum > 1 {
        Some(serde_json::json!({
            "kind": "local_manual_v1",
            "reason": "allow_local",
            "required_cluster_quorum": config.quorum,
            "actor": actor,
        }))
    } else {
        None
    };
    let operation = ledger.append_collision_resolution_with_agreement(
        &identity,
        collision_id,
        actor,
        resolution,
        agreement,
    )?;
    ledger.materialize_secret_value_versions()?;

    print_cluster_kv("collision_resolved", true);
    print_cluster_kv("collision_id", collision_id);
    print_cluster_kv("operation_id", operation.operation_id.as_str());
    print_cluster_kv("operation_type", operation.op_type.as_str());
    Ok(0)
}

async fn collect_collision_quorum_agreement(
    config: &ClusterConfig,
    identity: &NodeIdentity,
    ledger: &LedgerStore,
    collision: &LedgerCollision,
    resolution: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let required_peer_acks = usize::from(config.quorum.saturating_sub(1));
    let requester_latest_position = ledger.latest_position()?;
    let requester_latest_body_hash_b64 = ledger.latest_body_hash()?.unwrap_or_default();
    let nonce = format!(
        "hca_{}",
        valhall_config::ids::generate_entropy_prefixed_ulid()
    );
    let mut accepted = Vec::new();
    let mut failures = Vec::new();

    for peer in &config.peers {
        match request_peer_collision_approval(
            config,
            identity,
            peer,
            collision,
            resolution,
            nonce.as_str(),
            requester_latest_position,
            requester_latest_body_hash_b64.as_str(),
        )
        .await
        {
            Ok(evidence) => {
                accepted.push(evidence);
                if accepted.len() >= required_peer_acks {
                    break;
                }
            }
            Err(err) => failures.push(serde_json::json!({
                "peer_node_id": peer.node_id.as_str(),
                "endpoint": peer.endpoint.as_str(),
                "error": err.to_string(),
            })),
        }
    }

    if accepted.len() < required_peer_acks {
        let first_failure = failures
            .first()
            .and_then(|failure| failure.get("error"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-");
        return Err(format!(
            "collision resolution requires {required_peer_acks} reachable peer approval(s); accepted={} configured_peers={} failures={} first_failure={}",
            accepted.len(),
            config.peers.len(),
            failures.len(),
            first_failure
        )
        .into());
    }

    Ok(serde_json::json!({
        "kind": "collision_quorum_v1",
        "cluster_id": config.cluster_id.as_str(),
        "requester_node_id": identity.node_id.as_str(),
        "collision_id": collision.collision_id.as_str(),
        "scope": collision.scope.as_str(),
        "name": collision.name.as_str(),
        "key": collision.key.as_str(),
        "current_operation_id": collision.current_operation_id.as_str(),
        "incoming_operation_id": collision.incoming_operation_id.as_str(),
        "resolution": resolution,
        "required_cluster_quorum": config.quorum,
        "required_peer_acks": required_peer_acks,
        "nonce": nonce,
        "requester_latest_position": requester_latest_position,
        "requester_latest_body_hash_b64": requester_latest_body_hash_b64,
        "accepted": accepted,
        "failures": failures,
    }))
}

#[allow(clippy::too_many_arguments)]
async fn request_peer_collision_approval(
    config: &ClusterConfig,
    identity: &NodeIdentity,
    peer: &PeerConfig,
    collision: &LedgerCollision,
    resolution: &str,
    nonce: &str,
    requester_latest_position: i64,
    requester_latest_body_hash_b64: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let channel = Endpoint::from_shared(peer.endpoint.clone())?
        .connect_timeout(Duration::from_secs(CLUSTER_PEER_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(CLUSTER_PEER_RPC_TIMEOUT_SECS))
        .connect()
        .await?;
    let mut client = HemRuntimeClient::new(channel);
    let response = client
        .peer_approve_collision(signed_peer_transport_request(
            PeerApproveCollisionRequest {
                cluster_id: config.cluster_id.clone(),
                requester_node_id: identity.node_id.clone(),
                requester_public_key: identity.signing_public_key_b64.clone(),
                nonce: nonce.to_string(),
                collision_id: collision.collision_id.clone(),
                scope: collision.scope.clone(),
                name: collision.name.clone(),
                key: collision.key.clone(),
                current_operation_id: collision.current_operation_id.clone(),
                incoming_operation_id: collision.incoming_operation_id.clone(),
                base_version_seq: collision.base_version_seq,
                current_version_seq: collision.current_version_seq,
                resolution: resolution.to_string(),
                requester_latest_position,
                requester_latest_body_hash_b64: requester_latest_body_hash_b64.to_string(),
            },
            identity,
            config.cluster_id.as_str(),
            PEER_METHOD_APPROVE_COLLISION,
        )?)
        .await?
        .into_inner();

    if !response.accepted {
        let reason = if response.reason.trim().is_empty() {
            "-"
        } else {
            response.reason.as_str()
        };
        return Err(format!("peer rejected collision approval: {reason}").into());
    }
    if response.cluster_id != config.cluster_id {
        return Err(format!(
            "cluster_id mismatch expected={} actual={}",
            config.cluster_id, response.cluster_id
        )
        .into());
    }
    if response.node_id != peer.node_id {
        return Err(format!(
            "node_id mismatch expected={} actual={}",
            peer.node_id, response.node_id
        )
        .into());
    }
    if response.signing_public_key_b64 != peer.public_key {
        return Err("signing public key mismatch".into());
    }

    let statement = CollisionAgreementStatement {
        version: "hem-collision-agreement-v1",
        cluster_id: config.cluster_id.as_str(),
        requester_node_id: identity.node_id.as_str(),
        approver_node_id: response.node_id.as_str(),
        nonce,
        collision_id: collision.collision_id.as_str(),
        scope: collision.scope.as_str(),
        name: collision.name.as_str(),
        key: collision.key.as_str(),
        current_operation_id: collision.current_operation_id.as_str(),
        incoming_operation_id: collision.incoming_operation_id.as_str(),
        base_version_seq: collision.base_version_seq,
        current_version_seq: collision.current_version_seq,
        resolution,
        requester_latest_position,
        requester_latest_body_hash_b64,
        approver_latest_position: response.latest_position,
        approver_latest_body_hash_b64: response.latest_body_hash_b64.as_str(),
    };
    let statement_bytes = serde_json::to_vec(&statement)?;
    let expected_hash = node_statement_hash_b64(statement_bytes.as_slice());
    if response.statement_hash_b64 != expected_hash {
        return Err(format!(
            "statement hash mismatch expected={} actual={}",
            expected_hash, response.statement_hash_b64
        )
        .into());
    }
    verify_node_statement_signature(
        peer.public_key.as_str(),
        statement_bytes.as_slice(),
        response.signature_b64.as_str(),
    )?;
    let statement_json = serde_json::to_value(&statement)?;

    Ok(serde_json::json!({
        "peer_node_id": response.node_id,
        "endpoint": peer.endpoint.as_str(),
        "latest_position": response.latest_position,
        "latest_body_hash_b64": response.latest_body_hash_b64,
        "statement_hash_b64": response.statement_hash_b64,
        "signing_public_key_b64": response.signing_public_key_b64,
        "signature_b64": response.signature_b64,
        "statement": statement_json,
    }))
}

fn run_cluster_init(
    node_id: String,
    listen: String,
    quorum: u16,
    label: Option<String>,
    master_node_id: Option<String>,
    force: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    let data_dir = resolve_primary_data_dir();
    let config_path = data_dir.join(CLUSTER_CONFIG_FILE);
    let identity_path = data_dir.join(NODE_IDENTITY_FILE);
    if !force && (config_path.exists() || identity_path.exists()) {
        return Err(format!(
            "cluster files already exist in {}; pass --force to replace cluster.toml and node-identity.json",
            data_dir.display()
        )
        .into());
    }

    fs::create_dir_all(data_dir.as_path())?;
    let cluster_id = format!(
        "hmc_{}",
        valhall_config::ids::generate_entropy_prefixed_ulid()
    );
    let master_node_id = master_node_id.unwrap_or_else(|| node_id.clone());
    let config = ClusterConfig {
        enabled: true,
        cluster_id,
        node_id: node_id.clone(),
        listen,
        quorum,
        master_node_id: Some(master_node_id),
        peers: Vec::new(),
    };
    let identity = NodeIdentity::generate(node_id.as_str(), label.unwrap_or_default().as_str())?;

    config.save(config_path.as_path())?;
    identity.save(identity_path.as_path())?;

    print_cluster_kv("cluster_initialized", true);
    print_cluster_kv("data_dir", data_dir.display());
    print_cluster_kv("cluster_id", config.cluster_id.as_str());
    print_cluster_kv("node_id", config.node_id.as_str());
    print_cluster_kv("listen", config.listen.as_str());
    print_cluster_kv("quorum", config.quorum);
    Ok(0)
}

fn run_cluster_status() -> Result<i32, Box<dyn std::error::Error>> {
    let data_dir = resolve_primary_data_dir();
    let config_path = data_dir.join(CLUSTER_CONFIG_FILE);
    let identity_path = data_dir.join(NODE_IDENTITY_FILE);
    if !config_path.exists() {
        print_cluster_kv("cluster_enabled", false);
        print_cluster_kv("data_dir", data_dir.display());
        return Ok(0);
    }

    let config = ClusterConfig::load(config_path.as_path())?;
    let identity = NodeIdentity::load(identity_path.as_path())?;
    if identity.node_id != config.node_id {
        return Err(format!(
            "node identity mismatch: config node_id={} identity node_id={}",
            config.node_id, identity.node_id
        )
        .into());
    }

    print_cluster_kv("cluster_enabled", config.enabled);
    print_cluster_kv("data_dir", data_dir.display());
    print_cluster_kv("cluster_id", config.cluster_id.as_str());
    print_cluster_kv("node_id", config.node_id.as_str());
    print_cluster_kv("listen", config.listen.as_str());
    print_cluster_kv("quorum", config.quorum);
    print_cluster_kv(
        "master_node_id",
        config.master_node_id.as_deref().unwrap_or(""),
    );
    print_cluster_kv("peers", config.peers.len());
    print_cluster_kv(
        "identity_public_key",
        identity.signing_public_key_b64.as_str(),
    );
    let ledger = LedgerStore::open(data_dir.as_path())?;
    let checkpoints = ledger
        .list_checkpoints()?
        .into_iter()
        .filter(|checkpoint| checkpoint.body.cluster_id == config.cluster_id)
        .collect::<Vec<_>>();
    print_cluster_kv("checkpoints", checkpoints.len());
    if let Some(latest) = ledger.latest_checkpoint(config.cluster_id.as_str())? {
        print_cluster_kv("latest_checkpoint_id", latest.body.checkpoint_id.as_str());
        print_cluster_kv("latest_checkpoint_position", latest.body.to_position);
        print_cluster_kv("latest_checkpoint_hash", latest.body_hash_b64.as_str());
        let cosignatures =
            ledger.list_checkpoint_cosignatures(latest.body.checkpoint_id.as_str())?;
        print_cluster_kv("latest_checkpoint_cosignatures", cosignatures.len());
    } else {
        print_cluster_kv("latest_checkpoint_id", "");
        print_cluster_kv("latest_checkpoint_position", 0);
        print_cluster_kv("latest_checkpoint_hash", "");
        print_cluster_kv("latest_checkpoint_cosignatures", 0);
    }
    Ok(0)
}

fn run_cluster_health() -> Result<i32, Box<dyn std::error::Error>> {
    let data_dir = resolve_primary_data_dir();
    let config_path = data_dir.join(CLUSTER_CONFIG_FILE);
    let identity_path = data_dir.join(NODE_IDENTITY_FILE);
    if !config_path.exists() {
        print_cluster_kv("cluster_health", true);
        print_cluster_kv("cluster_health_status", "warning");
        print_cluster_kv("health_exit_code", 1);
        print_cluster_kv("cluster_enabled", false);
        print_cluster_kv("data_dir", data_dir.display());
        print_cluster_kv("health_error", "cluster_config_missing");
        return Ok(1);
    }

    let config = ClusterConfig::load(config_path.as_path())?;
    let identity = NodeIdentity::load(identity_path.as_path())?;
    if identity.node_id != config.node_id {
        print_cluster_kv("cluster_health", true);
        print_cluster_kv("cluster_health_status", "critical");
        print_cluster_kv("health_exit_code", 2);
        print_cluster_kv("cluster_enabled", config.enabled);
        print_cluster_kv("cluster_id", config.cluster_id.as_str());
        print_cluster_kv("node_id", config.node_id.as_str());
        print_cluster_kv("identity_node_id", identity.node_id.as_str());
        print_cluster_kv("divergence_issues", 1);
        print_cluster_kv("health_error", "node_identity_mismatch");
        return Ok(2);
    }

    let ledger = LedgerStore::open(data_dir.as_path())?;
    ledger.materialize_secret_value_versions()?;
    let report = ledger.verify_integrity()?;
    let latest_position = report.latest_position;
    let latest_body_hash = report.latest_body_hash_b64.clone();
    let collisions = ledger.list_open_collisions(config.cluster_id.as_str())?;
    let divergence_issues = report
        .issues
        .iter()
        .filter(|issue| issue.category == "divergence")
        .count();
    let error_issues = report
        .issues
        .iter()
        .filter(|issue| issue.severity == "error")
        .count();

    let mut healthy_peers = 0_usize;
    let mut lagging_peers = 0_usize;
    let mut offline_peers = 0_usize;
    let mut divergent_peers = 0_usize;
    let mut unknown_peers = 0_usize;
    for peer in &config.peers {
        let cursor = ledger.get_peer_cursor(peer.node_id.as_str())?;
        let (status, cursor_position, cursor_hash, last_seen, lag, error) = match cursor.as_ref() {
            Some(cursor) if cursor.last_position > latest_position => {
                divergent_peers += 1;
                (
                    "divergent",
                    cursor.last_position,
                    cursor.last_body_hash_b64.as_str(),
                    cursor.updated_at.to_rfc3339(),
                    0,
                    "cursor_ahead_of_local_head",
                )
            }
            Some(cursor)
                if cursor.last_position == latest_position
                    && cursor.last_body_hash_b64 == latest_body_hash =>
            {
                healthy_peers += 1;
                (
                    "caught_up",
                    cursor.last_position,
                    cursor.last_body_hash_b64.as_str(),
                    cursor.updated_at.to_rfc3339(),
                    0,
                    "",
                )
            }
            Some(cursor) if cursor.last_position == latest_position => {
                divergent_peers += 1;
                (
                    "divergent",
                    cursor.last_position,
                    cursor.last_body_hash_b64.as_str(),
                    cursor.updated_at.to_rfc3339(),
                    0,
                    "cursor_hash_mismatch",
                )
            }
            Some(cursor) => {
                lagging_peers += 1;
                (
                    "lagging",
                    cursor.last_position,
                    cursor.last_body_hash_b64.as_str(),
                    cursor.updated_at.to_rfc3339(),
                    latest_position.saturating_sub(cursor.last_position),
                    "",
                )
            }
            None if latest_position > 0 => {
                offline_peers += 1;
                (
                    "offline",
                    0,
                    "",
                    String::new(),
                    latest_position,
                    "missing_cursor",
                )
            }
            None => {
                unknown_peers += 1;
                ("unknown", 0, "", String::new(), 0, "missing_cursor")
            }
        };
        println!(
            "peer_health node_id={} status={} endpoint={} cursor_position={} cursor_hash={} lag={} last_seen={} error={}",
            peer.node_id,
            status,
            peer.endpoint,
            cursor_position,
            blank_dash(cursor_hash),
            lag,
            blank_dash(last_seen.as_str()),
            blank_dash(error)
        );
    }

    let latest_checkpoint = ledger.latest_checkpoint(config.cluster_id.as_str())?;
    let (checkpoint_status, checkpoint_id, checkpoint_position, checkpoint_cosignatures) =
        if let Some(checkpoint) = latest_checkpoint.as_ref() {
            let cosignatures =
                ledger.list_checkpoint_cosignatures(checkpoint.body.checkpoint_id.as_str())?;
            let quorum_met = usize::from(config.quorum) <= 1 + cosignatures.len();
            (
                if quorum_met {
                    "quorum_met"
                } else {
                    "pending_quorum"
                },
                checkpoint.body.checkpoint_id.as_str(),
                checkpoint.body.to_position,
                cosignatures.len(),
            )
        } else {
            ("none", "", 0, 0)
        };
    let available_peer_votes = healthy_peers + lagging_peers;
    let quorum_risk = usize::from(config.quorum) > 1 + available_peer_votes;
    let checkpoint_warning =
        latest_position > 0 && checkpoint_status != "quorum_met" && config.quorum > 1;
    let critical = error_issues > 0 || divergent_peers > 0;
    let warning = !critical
        && (!collisions.is_empty()
            || lagging_peers > 0
            || offline_peers > 0
            || unknown_peers > 0
            || quorum_risk
            || checkpoint_warning);
    let (health_status, exit_code) = if critical {
        ("critical", 2)
    } else if warning {
        ("warning", 1)
    } else {
        ("healthy", 0)
    };

    print_cluster_kv("cluster_health", true);
    print_cluster_kv("cluster_health_status", health_status);
    print_cluster_kv("health_exit_code", exit_code);
    print_cluster_kv("cluster_enabled", config.enabled);
    print_cluster_kv("data_dir", data_dir.display());
    print_cluster_kv("cluster_id", config.cluster_id.as_str());
    print_cluster_kv("node_id", config.node_id.as_str());
    print_cluster_kv("listen", config.listen.as_str());
    print_cluster_kv("quorum", config.quorum);
    print_cluster_kv("configured_peers", config.peers.len());
    print_cluster_kv("latest_position", latest_position);
    print_cluster_kv("latest_body_hash", latest_body_hash.as_str());
    print_cluster_kv("ledger_ok", report.ok);
    print_cluster_kv("integrity_issues", report.issues.len());
    print_cluster_kv("error_issues", error_issues);
    print_cluster_kv("divergence_issues", divergence_issues);
    print_cluster_kv("collisions", collisions.len());
    print_cluster_kv("healthy_peers", healthy_peers);
    print_cluster_kv("lagging_peers", lagging_peers);
    print_cluster_kv("offline_peers", offline_peers);
    print_cluster_kv("unknown_peers", unknown_peers);
    print_cluster_kv("divergent_peers", divergent_peers);
    print_cluster_kv("quorum_risk", quorum_risk);
    print_cluster_kv("checkpoint_status", checkpoint_status);
    print_cluster_kv("latest_checkpoint_id", checkpoint_id);
    print_cluster_kv("latest_checkpoint_position", checkpoint_position);
    print_cluster_kv("latest_checkpoint_cosignatures", checkpoint_cosignatures);
    print_cluster_kv("sync_errors", offline_peers + divergent_peers);
    for issue in &report.issues {
        println!(
            "health_issue severity={} category={} reference={} message={}",
            issue.severity, issue.category, issue.reference, issue.message
        );
    }
    for collision in collisions {
        println!(
            "collision_health collision_id={} scope={} name={} key={} current_operation_id={} incoming_operation_id={}",
            collision.collision_id,
            collision.scope,
            collision.name,
            collision.key,
            collision.current_operation_id,
            collision.incoming_operation_id
        );
    }
    Ok(exit_code)
}

fn run_cluster_peers() -> Result<i32, Box<dyn std::error::Error>> {
    let data_dir = resolve_primary_data_dir();
    let config_path = data_dir.join(CLUSTER_CONFIG_FILE);
    if !config_path.exists() {
        print_cluster_kv("peers", 0);
        return Ok(0);
    }

    let config = ClusterConfig::load(config_path.as_path())?;
    print_cluster_kv("peers", config.peers.len());
    for peer in config.peers {
        print_cluster_peer(&peer);
    }
    Ok(0)
}

fn resolve_primary_data_dir() -> PathBuf {
    if let Ok(value) = std::env::var("HEM_DATA_DIR") {
        if let Some(value) = normalize_optional_string(value) {
            return PathBuf::from(value);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(DEFAULT_HEM_SUBDIR);
    }
    PathBuf::from(DEFAULT_HEM_SUBDIR)
}

fn run_policy_command(command: PolicyCommands) -> Result<i32, Box<dyn std::error::Error>> {
    let data_dir = resolve_primary_data_dir();
    let store = PolicyStore::open(data_dir.as_path())?;
    match command {
        PolicyCommands::List => {
            let snapshot = store.snapshot()?;
            print_cluster_kv("default_tier", snapshot.default_tier.as_str());
            print_cluster_kv("scope_policies", snapshot.scope_tiers.len());
            for binding in snapshot.scope_tiers {
                println!(
                    "scope target={} tier={}",
                    binding.target,
                    binding.tier.as_str()
                );
            }
            print_cluster_kv("secret_policies", snapshot.secret_tiers.len());
            for binding in snapshot.secret_tiers {
                println!(
                    "secret target={} tier={}",
                    binding.target,
                    binding.tier.as_str()
                );
            }
        }
        PolicyCommands::Get { scope, secret } => {
            let target = parse_policy_target(scope, secret)?;
            let tier = effective_policy_for_target(&store, &target)?;
            print_cluster_kv("target", target.label());
            print_cluster_kv("effective_tier", tier.as_str());
        }
        PolicyCommands::Set {
            tier,
            scope,
            secret,
            allow_downgrade,
        } => {
            let tier = CoreSecretPolicyTier::parse(tier.as_str())?;
            let target = parse_policy_target(scope, secret)?;
            let previous = effective_policy_for_target(&store, &target)?;
            if policy_tier_rank(tier) < policy_tier_rank(previous) && !allow_downgrade {
                return Err(format!(
                    "policy downgrade from {} to {} requires --allow-downgrade",
                    previous.as_str(),
                    tier.as_str()
                )
                .into());
            }

            match &target {
                PolicyTarget::Default => store.set_default_policy(tier)?,
                PolicyTarget::Scope { scope, .. } => store.set_scope_policy(scope, tier)?,
                PolicyTarget::Secret { scope, name, .. } => {
                    store.set_secret_policy(scope, name.as_str(), tier)?;
                }
            }
            print_cluster_kv("policy_set", true);
            print_cluster_kv("target", target.label());
            print_cluster_kv("previous_tier", previous.as_str());
            print_cluster_kv("tier", tier.as_str());
            print_cluster_kv("allow_downgrade", allow_downgrade);
        }
    }
    Ok(0)
}

fn run_lease_command(command: LeaseCommands) -> Result<i32, Box<dyn std::error::Error>> {
    let data_dir = resolve_primary_data_dir();
    let store = PolicyStore::open(data_dir.as_path())?;
    match command {
        LeaseCommands::Issue {
            secret,
            requester,
            node_id,
            uses,
            ttl_seconds,
        } => {
            let (scope, name, _) = parse_core_secret_ref(secret.as_str())?;
            let lease = store.issue_offline_lease(IssueOfflineLeaseInput {
                scope,
                name,
                requester,
                node_id,
                max_uses: uses,
                ttl_seconds,
            })?;
            print_cluster_kv("lease_issued", true);
            print_offline_lease(&lease);
        }
        LeaseCommands::List => {
            let leases = store.list_offline_leases()?;
            print_cluster_kv("leases", leases.len());
            for lease in leases {
                print_offline_lease(&lease);
            }
        }
        LeaseCommands::Consume {
            secret,
            requester,
            node_id,
        } => {
            let (scope, name, _) = parse_core_secret_ref(secret.as_str())?;
            let lease = store.consume_offline_lease(
                &scope,
                name.as_str(),
                requester.as_str(),
                node_id.as_str(),
            )?;
            print_cluster_kv("lease_consumed", true);
            print_offline_lease(&lease);
        }
        LeaseCommands::Revoke { lease_id, actor } => {
            let lease = store.revoke_offline_lease(lease_id.as_str(), actor.as_str())?;
            print_cluster_kv("lease_revoked", true);
            print_offline_lease(&lease);
        }
    }
    Ok(0)
}

#[derive(Debug, Clone)]
enum PolicyTarget {
    Default,
    Scope {
        scope: hem_core::SecretScope,
        label: String,
    },
    Secret {
        scope: hem_core::SecretScope,
        name: String,
        label: String,
    },
}

impl PolicyTarget {
    fn label(&self) -> &str {
        match self {
            Self::Default => "default",
            Self::Scope { label, .. } | Self::Secret { label, .. } => label.as_str(),
        }
    }
}

fn parse_policy_target(
    scope: Option<String>,
    secret: Option<String>,
) -> Result<PolicyTarget, Box<dyn std::error::Error>> {
    if let Some(secret) = secret {
        let (scope, name, label) = parse_core_secret_ref(secret.as_str())?;
        return Ok(PolicyTarget::Secret { scope, name, label });
    }
    if let Some(scope) = scope {
        let selector = parse_scope_selector_value(scope.as_str())?;
        let core_scope = proto_scope_to_core(&selector)?;
        return Ok(PolicyTarget::Scope {
            scope: core_scope,
            label: format_scope(&selector),
        });
    }
    Ok(PolicyTarget::Default)
}

fn effective_policy_for_target(
    store: &PolicyStore,
    target: &PolicyTarget,
) -> Result<CoreSecretPolicyTier, Box<dyn std::error::Error>> {
    let snapshot = store.snapshot()?;
    match target {
        PolicyTarget::Default => Ok(snapshot.default_tier),
        PolicyTarget::Scope { label, .. } => Ok(snapshot
            .scope_tiers
            .iter()
            .find(|item| item.target == *label)
            .map(|item| item.tier)
            .unwrap_or(snapshot.default_tier)),
        PolicyTarget::Secret { scope, name, .. } => Ok(store.effective_policy(scope, name)?),
    }
}

fn parse_core_secret_ref(
    value: &str,
) -> Result<(hem_core::SecretScope, String, String), Box<dyn std::error::Error>> {
    let secret = parse_secret_ref_or_global(value)?;
    let scope = proto_scope_to_core(secret.scope.as_ref().ok_or("secret scope is required")?)?;
    let label = format!(
        "{}/{}",
        secret
            .scope
            .as_ref()
            .map(format_scope)
            .unwrap_or_else(|| "global".to_string()),
        secret.name
    );
    Ok((scope, secret.name, label))
}

fn policy_tier_rank(tier: CoreSecretPolicyTier) -> u8 {
    match tier {
        CoreSecretPolicyTier::LocalLogged => 0,
        CoreSecretPolicyTier::OfflineLease => 1,
        CoreSecretPolicyTier::PeerQuorum => 2,
        CoreSecretPolicyTier::MasterBiometric => 3,
    }
}

fn print_offline_lease(lease: &OfflineLease) {
    print_cluster_kv("lease_id", lease.lease_id.as_str());
    print_cluster_kv("scope", core_scope_label(&lease.scope));
    print_cluster_kv("name", lease.name.as_str());
    print_cluster_kv("requester", lease.requester.as_str());
    print_cluster_kv("node_id", lease.node_id.as_str());
    print_cluster_kv("max_uses", lease.max_uses);
    print_cluster_kv("remaining_uses", lease.remaining_uses);
    print_cluster_kv("issued_at", lease.issued_at.to_rfc3339());
    print_cluster_kv("expires_at", lease.expires_at.to_rfc3339());
    if let Some(revoked_at) = lease.revoked_at {
        print_cluster_kv("revoked_at", revoked_at.to_rfc3339());
    }
    if let Some(revoked_by) = lease.revoked_by.as_ref() {
        print_cluster_kv("revoked_by", revoked_by.as_str());
    }
}

fn core_scope_label(scope: &hem_core::SecretScope) -> String {
    match scope {
        hem_core::SecretScope::Global => "global".to_string(),
        hem_core::SecretScope::Project { project } => format!("project/{project}"),
        hem_core::SecretScope::Identity { identity_id } => format!("identity/{identity_id}"),
    }
}

fn print_cluster_peer(peer: &PeerConfig) {
    println!(
        "peer node_id={} endpoint={} public_key={} wrap_public_key={}",
        peer.node_id,
        peer.endpoint,
        peer.public_key,
        peer.wrap_public_key.as_deref().unwrap_or("")
    );
}

fn proto_envelope_from_operation(operation: &LedgerOperation) -> proto::LedgerOperationEnvelope {
    proto::LedgerOperationEnvelope {
        body: Some(proto::LedgerOperationBody {
            operation_id: operation.operation_id.clone(),
            cluster_id: operation.cluster_id.clone(),
            node_id: operation.node_id.clone(),
            node_seq: operation.node_seq,
            op_type: operation.op_type.clone(),
            payload_json: operation.payload_json.to_string(),
            created_at: operation.created_at.to_rfc3339(),
            prev_hash_b64: operation.prev_hash_b64.clone(),
        }),
        body_hash_b64: operation.body_hash_b64.clone(),
        signing_public_key_b64: operation.signing_public_key_b64.clone(),
        signature_b64: operation.signature_b64.clone(),
        position: operation.position,
    }
}

fn core_envelope_from_proto(
    operation: proto::LedgerOperationEnvelope,
) -> Result<LedgerOperationEnvelope, Box<dyn std::error::Error>> {
    let body = operation.body.ok_or("ledger operation body is required")?;
    Ok(LedgerOperationEnvelope {
        body: LedgerOperationBody {
            operation_id: body.operation_id,
            cluster_id: body.cluster_id,
            node_id: body.node_id,
            node_seq: body.node_seq,
            op_type: body.op_type,
            payload_json: serde_json::from_str(body.payload_json.as_str())?,
            created_at: chrono::DateTime::parse_from_rfc3339(body.created_at.as_str())?
                .with_timezone(&chrono::Utc),
            prev_hash_b64: body.prev_hash_b64,
        },
        body_hash_b64: operation.body_hash_b64,
        signing_public_key_b64: operation.signing_public_key_b64,
        signature_b64: operation.signature_b64,
    })
}

fn print_cluster_collision(collision: &LedgerCollision) {
    println!(
        "collision id={} secret={}/{} key={} current_operation={} incoming_operation={} base_version_seq={} current_version_seq={} created_at={}",
        collision.collision_id,
        collision.scope,
        collision.name,
        collision.key,
        collision.current_operation_id,
        collision.incoming_operation_id,
        collision.base_version_seq,
        collision.current_version_seq,
        collision.created_at.to_rfc3339()
    );
}

fn print_cluster_kv(key: &str, value: impl std::fmt::Display) {
    println!("{key}={value}");
}

fn daemon_endpoint(override_value: Option<String>) -> String {
    override_value
        .or_else(|| std::env::var("VALHALL_HEMD_ENDPOINT").ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:50091".to_string())
}

fn resolve_archive_dir() -> PathBuf {
    if let Ok(value) = std::env::var("VALHALL_HEM_ARCHIVE_DIR") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".valhall/hem/archive");
    }
    PathBuf::from(".valhall/hem/archive")
}

fn default_archive_path(scope: &str, name: &str) -> PathBuf {
    let safe_scope = scope.replace('/', "_");
    let safe_name = name.replace('/', "_");
    resolve_archive_dir().join(format!(
        "{}-{}-{}.json",
        now_epoch_ms(),
        safe_scope,
        safe_name
    ))
}

fn default_export_path() -> PathBuf {
    resolve_archive_dir().join(format!("{}-hem-export.bin", now_epoch_ms()))
}

fn signed_peer_transport_request<T>(
    message: T,
    identity: &NodeIdentity,
    cluster_id: &str,
    method: &str,
) -> Result<Request<T>, Box<dyn std::error::Error>> {
    let nonce = format!(
        "hpt_{}",
        valhall_config::ids::generate_entropy_prefixed_ulid()
    );
    let timestamp_unix = Utc::now().timestamp();
    let statement_bytes = peer_transport_auth_statement_bytes(
        cluster_id,
        identity.node_id.as_str(),
        method,
        nonce.as_str(),
        timestamp_unix,
    )?;
    let signature = identity.sign_statement(statement_bytes.as_slice())?;

    let mut request = Request::new(message);
    let metadata = request.metadata_mut();
    metadata.insert(
        PEER_TRANSPORT_AUTH_CLUSTER_ID_METADATA_KEY,
        cluster_id.parse()?,
    );
    metadata.insert(
        PEER_TRANSPORT_AUTH_NODE_ID_METADATA_KEY,
        identity.node_id.parse()?,
    );
    metadata.insert(PEER_TRANSPORT_AUTH_METHOD_METADATA_KEY, method.parse()?);
    metadata.insert(PEER_TRANSPORT_AUTH_NONCE_METADATA_KEY, nonce.parse()?);
    metadata.insert(
        PEER_TRANSPORT_AUTH_TIMESTAMP_METADATA_KEY,
        timestamp_unix.to_string().parse()?,
    );
    metadata.insert(
        PEER_TRANSPORT_AUTH_SIGNATURE_METADATA_KEY,
        signature.parse()?,
    );
    Ok(request)
}

async fn connect_client(
    endpoint: &str,
    token: Option<String>,
) -> Result<
    HemRuntimeClient<InterceptedService<Channel, BearerAuthInterceptor>>,
    Box<dyn std::error::Error>,
> {
    let channel = Endpoint::from_shared(endpoint.to_string())?
        .connect()
        .await?;
    let interceptor = BearerAuthInterceptor::new(token)?;
    Ok(HemRuntimeClient::with_interceptor(channel, interceptor))
}

fn resolve_auth_token(override_value: Option<String>) -> Option<String> {
    override_value
        .or_else(|| std::env::var("VALHALL_HEM_TOKEN").ok())
        .and_then(normalize_optional_string)
        .or_else(load_operator_token)
}

fn load_operator_token() -> Option<String> {
    for dir in operator_token_dirs() {
        let path = dir.join(OPERATOR_TOKEN_FILE);
        if let Some(token) = fs::read_to_string(path.as_path())
            .ok()
            .and_then(normalize_optional_string)
        {
            return Some(token);
        }
    }
    None
}

fn operator_token_dirs() -> Vec<PathBuf> {
    let mut out = Vec::new();

    if let Ok(value) = std::env::var("HEM_DATA_DIR") {
        if let Some(value) = normalize_optional_string(value) {
            out.push(PathBuf::from(value));
        }
    }
    if let Ok(value) = std::env::var("VALHALL_SYSTEM_DAEMONS_DIR") {
        if let Some(value) = normalize_optional_string(value) {
            out.push(PathBuf::from(value).join("data/hem"));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        out.push(PathBuf::from(home.as_str()).join(DEFAULT_HEM_SUBDIR));
        out.push(PathBuf::from(home.as_str()).join(DEFAULT_HEM_SYSTEM_DAEMONS_SUBDIR));
    }
    out
}

#[derive(Clone, Debug)]
struct BearerAuthInterceptor {
    value: Option<MetadataValue<tonic::metadata::Ascii>>,
}

impl BearerAuthInterceptor {
    fn new(token: Option<String>) -> Result<Self, Box<dyn std::error::Error>> {
        let value = match token {
            Some(token) => {
                let rendered = format!("Bearer {}", token.trim());
                Some(MetadataValue::try_from(rendered.as_str())?)
            }
            None => None,
        };
        Ok(Self { value })
    }
}

impl Interceptor for BearerAuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if let Some(value) = self.value.as_ref() {
            request
                .metadata_mut()
                .insert(AUTHORIZATION_METADATA_KEY, value.clone());
        }
        Ok(request)
    }
}

fn parse_values(values: Vec<String>) -> Result<Vec<SecretValue>, Box<dyn std::error::Error>> {
    if values.is_empty() {
        return Err("at least one key=value pair required".into());
    }
    let mut out = Vec::with_capacity(values.len());
    for item in values {
        let (key, value) = parse_set_value_entry(item.as_str(), false)?;
        out.push(secret_value_from_parts(key.as_str(), value.as_deref())?);
    }
    Ok(out)
}

fn build_set_values(
    existing: Vec<SecretValue>,
    imported: Vec<SecretValue>,
    explicit: Vec<SecretValue>,
) -> Vec<SecretValue> {
    merge_secret_values(existing, merge_secret_values(imported, explicit))
}

fn merge_secret_values(base: Vec<SecretValue>, overrides: Vec<SecretValue>) -> Vec<SecretValue> {
    let mut merged = BTreeMap::<String, String>::new();
    for entry in base {
        merged.insert(entry.key, entry.value);
    }
    for entry in overrides {
        merged.insert(entry.key, entry.value);
    }
    merged
        .into_iter()
        .map(|(key, value)| SecretValue { key, value })
        .collect()
}

fn secret_values_from_map(values: HashMap<String, String>) -> Vec<SecretValue> {
    values
        .into_iter()
        .map(|(key, value)| SecretValue { key, value })
        .collect()
}

async fn fetch_existing_secret_values(
    client: &mut HemRuntimeClient<InterceptedService<Channel, BearerAuthInterceptor>>,
    secret_ref: &SecretRef,
) -> Result<Vec<SecretValue>, Box<dyn std::error::Error>> {
    let response = match client
        .get_secret(GetSecretRequest {
            lookup: Some(get_secret_request::Lookup::Secret(secret_ref.clone())),
            context: Some(ScopeResolutionContext {
                identity_id: String::new(),
                project: String::new(),
            }),
            key: String::new(),
            async_read: false,
            wait_timeout_ms: 0,
            reason: "merge existing values for interactive hem set".to_string(),
            approval_receipt: String::new(),
        })
        .await
    {
        Ok(response) => response.into_inner(),
        Err(status) if status.code() == Code::NotFound => return Ok(Vec::new()),
        Err(status) => return Err(status.into()),
    };

    match response.result {
        Some(get_secret_response::Result::Secret(secret)) => {
            Ok(secret_values_from_map(secret.values))
        }
        Some(get_secret_response::Result::Pending(pending)) => Err(format!(
            "interactive set could not merge existing keys because reading the current secret is pending approval request_id={}",
            pending.request_id
        )
        .into()),
        None => Err("missing get response result".into()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OpItemLocator {
    item: String,
    vault: Option<String>,
}

fn parse_op_item_locator(reference: &str) -> Result<OpItemLocator, Box<dyn std::error::Error>> {
    let trimmed = reference.trim();
    if trimmed.is_empty() {
        return Err("--from-op-item requires a non-empty item reference".into());
    }

    if let Some(rest) = trimmed.strip_prefix("op://") {
        let parts: Vec<&str> = rest.split('/').filter(|part| !part.is_empty()).collect();
        if parts.len() != 2 {
            return Err("op:// item reference for --from-op-item must be op://<vault>/<item>; for single field import use KEY=op://<vault>/<item>/<field>".into());
        }
        return Ok(OpItemLocator {
            vault: Some(parts[0].to_string()),
            item: parts[1].to_string(),
        });
    }

    Ok(OpItemLocator {
        item: trimmed.to_string(),
        vault: None,
    })
}

fn read_op_item_values(reference: &str) -> Result<Vec<SecretValue>, Box<dyn std::error::Error>> {
    let locator = parse_op_item_locator(reference)?;
    let mut command = Command::new("op");
    command
        .arg("item")
        .arg("get")
        .arg(locator.item.as_str())
        .arg("--format")
        .arg("json")
        .arg("--reveal");
    if let Some(vault) = locator.vault.as_deref() {
        command.arg("--vault").arg(vault);
    }

    let output = command
        .output()
        .map_err(|err| format!("failed to run `op item get`: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(output.stderr.as_slice());
        return Err(format!("`op item get` failed for {reference}: {}", stderr.trim()).into());
    }

    let body = String::from_utf8(output.stdout)?;
    parse_op_item_json_values(body.as_str())
}

fn parse_op_item_json_values(body: &str) -> Result<Vec<SecretValue>, Box<dyn std::error::Error>> {
    let parsed: serde_json::Value = serde_json::from_str(body)?;
    let fields = parsed
        .get("fields")
        .and_then(serde_json::Value::as_array)
        .ok_or("`op item get` output missing fields array")?;

    let mut out = Vec::<SecretValue>::new();
    let mut seen = BTreeMap::<String, usize>::new();

    for field in fields {
        let Some(object) = field.as_object() else {
            continue;
        };
        let Some(raw_value) = object.get("value") else {
            continue;
        };
        let Some(value) = op_item_field_value(raw_value) else {
            continue;
        };
        let Some(key) = op_item_field_key(object) else {
            continue;
        };

        if key.contains('/') || key.contains('\0') || key.contains("..") {
            return Err(format!(
                "1Password field key {key:?} cannot be used as Hem key; use explicit KEY=op://... instead"
            )
            .into());
        }
        if seen.insert(key.clone(), out.len()).is_some() {
            return Err(format!(
                "duplicate 1Password field key {key:?}; rename field or use explicit KEY=VALUE overrides"
            )
            .into());
        }

        out.push(SecretValue { key, value });
    }

    if out.is_empty() {
        return Err("1Password item has no non-empty fields to import".into());
    }
    Ok(out)
}

fn op_item_field_key(object: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    for candidate in ["id", "label", "purpose"] {
        let Some(value) = object.get(candidate).and_then(serde_json::Value::as_str) else {
            continue;
        };
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn op_item_field_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(inner) => Some(inner.to_string()),
        serde_json::Value::Bool(inner) => Some(inner.to_string()),
        serde_json::Value::Number(inner) => Some(inner.to_string()),
        other => Some(other.to_string()),
    }
}

fn collect_interactive_values(
    values: Vec<String>,
) -> Result<Vec<SecretValue>, Box<dyn std::error::Error>> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("interactive set requires a TTY".into());
    }

    let mut out = Vec::new();

    if values.is_empty() {
        loop {
            let key = prompt_input("key (blank to finish): ")?;
            let key = key.trim().to_string();
            if key.is_empty() {
                if out.is_empty() {
                    return Err("at least one key/value pair required".into());
                }
                break;
            }
            let value = rpassword::prompt_password(format!("value for {key}: "))?;
            out.push(secret_value_from_parts(key.as_str(), Some(value.as_str()))?);
        }
        return Ok(out);
    }

    for item in values {
        let (key, value) = parse_set_value_entry(item.as_str(), true)?;
        let value = match value {
            Some(value) => value,
            None => rpassword::prompt_password(format!("value for {key}: "))?,
        };
        out.push(secret_value_from_parts(key.as_str(), Some(value.as_str()))?);
    }
    Ok(out)
}

fn prompt_input(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input)
}

fn parse_set_value_entry(
    item: &str,
    allow_key_only: bool,
) -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
    if let Some((key, value)) = item.split_once('=') {
        let key = key.trim();
        if key.is_empty() {
            return Err(format!("invalid empty key in pair: {item}").into());
        }
        return Ok((key.to_string(), Some(value.to_string())));
    }

    if allow_key_only {
        let key = item.trim();
        if key.is_empty() {
            return Err("secret key must not be empty".into());
        }
        return Ok((key.to_string(), None));
    }

    Err(format!("invalid key=value pair: {item}").into())
}

fn secret_value_from_parts(
    key: &str,
    value: Option<&str>,
) -> Result<SecretValue, Box<dyn std::error::Error>> {
    let key = key.trim();
    if key.is_empty() {
        return Err("secret key must not be empty".into());
    }
    let value = value.unwrap_or_default();
    Ok(SecretValue {
        key: key.to_string(),
        value: resolve_value_source(value.to_string())?,
    })
}

fn required_secret_key_value(
    secret: &proto::SecretWithValues,
    key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    secret
        .values
        .get(key)
        .cloned()
        .ok_or_else(|| format!("missing requested key '{key}' in get response").into())
}

fn resolve_value_source(value: String) -> Result<String, Box<dyn std::error::Error>> {
    resolve_value_source_with(value, read_op_reference)
}

fn resolve_value_source_with<F>(
    value: String,
    mut op_reader: F,
) -> Result<String, Box<dyn std::error::Error>>
where
    F: FnMut(&str) -> Result<String, Box<dyn std::error::Error>>,
{
    let candidate = value.trim();
    if candidate.starts_with("op://") {
        return op_reader(candidate);
    }
    Ok(value)
}

fn read_op_reference(reference: &str) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("op")
        .arg("read")
        .arg(reference)
        .output()
        .map_err(|err| format!("failed to run `op read`: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(output.stderr.as_slice());
        return Err(format!("`op read` failed for {reference}: {}", stderr.trim()).into());
    }

    let mut value = String::from_utf8(output.stdout)?;
    while value.ends_with('\n') || value.ends_with('\r') {
        value.pop();
    }
    Ok(value)
}

fn parse_lookup(value: &str) -> Result<get_secret_request::Lookup, Box<dyn std::error::Error>> {
    if value.contains('/') {
        Ok(get_secret_request::Lookup::Secret(
            parse_secret_ref_or_global(value)?,
        ))
    } else {
        let name = value.trim();
        if name.is_empty() {
            return Err("secret name must not be empty".into());
        }
        Ok(get_secret_request::Lookup::Name(name.to_string()))
    }
}

fn parse_secret_ref_or_global(value: &str) -> Result<SecretRef, Box<dyn std::error::Error>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("secret reference must not be empty".into());
    }

    if !trimmed.contains('/') {
        return Ok(SecretRef {
            scope: Some(ScopeSelector {
                scope: SecretScope::Global as i32,
                project: String::new(),
                identity_id: String::new(),
            }),
            name: trimmed.to_string(),
        });
    }

    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts.len() < 2 {
        return Err(format!("invalid secret reference: {trimmed}").into());
    }

    match parts[0] {
        "global" => {
            if parts.len() != 2 {
                return Err(format!("global scope expects global/<name>, got: {trimmed}").into());
            }
            Ok(SecretRef {
                scope: Some(ScopeSelector {
                    scope: SecretScope::Global as i32,
                    project: String::new(),
                    identity_id: String::new(),
                }),
                name: parts[1].to_string(),
            })
        }
        "project" => {
            if parts.len() != 3 {
                return Err(format!(
                    "project scope expects project/<project>/<name>, got: {trimmed}"
                )
                .into());
            }
            Ok(SecretRef {
                scope: Some(ScopeSelector {
                    scope: SecretScope::Project as i32,
                    project: parts[1].to_string(),
                    identity_id: String::new(),
                }),
                name: parts[2].to_string(),
            })
        }
        "identity" => {
            if parts.len() != 3 {
                return Err(format!(
                    "identity scope expects identity/<identity_id>/<name>, got: {trimmed}"
                )
                .into());
            }
            Ok(SecretRef {
                scope: Some(ScopeSelector {
                    scope: SecretScope::Identity as i32,
                    project: String::new(),
                    identity_id: parts[1].to_string(),
                }),
                name: parts[2].to_string(),
            })
        }
        _ => Err(format!(
            "unknown scope prefix in secret reference: {trimmed}\naccepted formats: {SECRET_REF_FORMATS}\nfor global secrets, use an unscoped name like: hem set my-secret key=value"
        )
        .into()),
    }
}

fn parse_scope_selector_value(value: &str) -> Result<ScopeSelector, Box<dyn std::error::Error>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("scope must not be empty".into());
    }
    if trimmed == "global" {
        return Ok(ScopeSelector {
            scope: SecretScope::Global as i32,
            project: String::new(),
            identity_id: String::new(),
        });
    }

    let parts: Vec<&str> = trimmed.split('/').collect();
    match parts.as_slice() {
        ["project", project] if !project.trim().is_empty() => Ok(ScopeSelector {
            scope: SecretScope::Project as i32,
            project: (*project).to_string(),
            identity_id: String::new(),
        }),
        ["identity", identity_id] if !identity_id.trim().is_empty() => Ok(ScopeSelector {
            scope: SecretScope::Identity as i32,
            project: String::new(),
            identity_id: (*identity_id).to_string(),
        }),
        _ => Err(format!(
            "invalid scope {trimmed:?}; expected: global | project/<project> | identity/<identity_id>"
        )
        .into()),
    }
}

fn format_scope(scope: &ScopeSelector) -> String {
    match SecretScope::try_from(scope.scope).unwrap_or(SecretScope::Unspecified) {
        SecretScope::Global => "global".to_string(),
        SecretScope::Project => format!("project/{}", scope.project),
        SecretScope::Identity => format!("identity/{}", scope.identity_id),
        SecretScope::Unspecified => "unspecified".to_string(),
    }
}

fn normalize_query(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("query must not be empty".into());
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn normalize_optional_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn approval_state_label(value: i32) -> &'static str {
    match proto::ApprovalState::try_from(value).unwrap_or(proto::ApprovalState::Unspecified) {
        proto::ApprovalState::Pending => "pending",
        proto::ApprovalState::Approved => "approved",
        proto::ApprovalState::Denied => "denied",
        proto::ApprovalState::TimedOut => "timed_out",
        proto::ApprovalState::Unspecified => "unspecified",
    }
}

fn token_scope_arg_to_proto(scope: TokenScopeArg) -> i32 {
    match scope {
        TokenScopeArg::Global => proto::SecretScope::Global as i32,
        TokenScopeArg::Project => proto::SecretScope::Project as i32,
        TokenScopeArg::Identity => proto::SecretScope::Identity as i32,
    }
}

fn token_type_arg_to_proto(token_type: TokenTypeArg) -> i32 {
    match token_type {
        TokenTypeArg::Operator => proto::TokenType::Operator as i32,
        TokenTypeArg::Service => proto::TokenType::Service as i32,
        TokenTypeArg::AgentRun => proto::TokenType::AgentRun as i32,
    }
}

fn format_token_type(token_type: proto::TokenType) -> &'static str {
    match token_type {
        proto::TokenType::Operator => "operator",
        proto::TokenType::Service => "service",
        proto::TokenType::AgentRun => "agent_run",
        proto::TokenType::Unspecified => "unspecified",
    }
}

fn blank_dash(value: &str) -> &str {
    if value.trim().is_empty() {
        "-"
    } else {
        value
    }
}

fn print_token_info(info: &proto::TokenInfo) {
    let token_type =
        proto::TokenType::try_from(info.token_type).unwrap_or(proto::TokenType::Unspecified);
    print_kv("token_id", &info.token_id);
    print_kv("token_type", format_token_type(token_type));
    print_kv("issued_at", &info.issued_at);
    print_kv("expires_at", &info.expires_at);
    print_kv("issued_by", &info.issued_by);
    if !info.service_name.trim().is_empty() {
        print_kv("service_name", &info.service_name);
    }
    if !info.identity_id.trim().is_empty() {
        print_kv("identity_id", &info.identity_id);
    }
    if !info.project.trim().is_empty() {
        print_kv("project", &info.project);
    }
    if !info.scopes.is_empty() {
        let scopes = info
            .scopes
            .iter()
            .map(|item| {
                match proto::SecretScope::try_from(*item).unwrap_or(proto::SecretScope::Unspecified)
                {
                    proto::SecretScope::Global => "global",
                    proto::SecretScope::Project => "project",
                    proto::SecretScope::Identity => "identity",
                    proto::SecretScope::Unspecified => "unspecified",
                }
            })
            .collect::<Vec<&str>>()
            .join(",");
        print_kv("scopes", scopes);
    }
}

fn confirm_human_approval(
    request_id: &str,
    approve: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(
            "approval action must run in interactive terminal (human confirmation required)".into(),
        );
    }

    let verb = if approve { "APPROVE" } else { "DENY" };
    let challenge = format!("{verb} {request_id}");
    print!("Type '{challenge}' to confirm: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if input.trim() != challenge {
        return Err("confirmation did not match; approval action canceled".into());
    }
    Ok(())
}

async fn confirm_biometric_approval(
    client: &mut HemRuntimeClient<InterceptedService<Channel, BearerAuthInterceptor>>,
    request_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = client
        .list_pending_approvals(ListPendingApprovalsRequest { limit: 500 })
        .await?
        .into_inner();
    let request = response
        .requests
        .iter()
        .find(|item| item.request_id == request_id)
        .ok_or_else(|| format!("pending approval request not found: {request_id}"))?;
    let challenge = approval_challenge_from_proto(request)?;
    let adapter = PlatformBiometricApprovalAdapter::detect();
    let capability = adapter.capability();
    let kind = capability.biometric_kind.as_deref().ok_or_else(|| {
        "platform biometric approval unavailable on this node; use typed confirmation fallback"
            .to_string()
    })?;
    let decision = adapter.approve(
        &challenge,
        ApprovalCredential::BiometricAssertion {
            kind,
            assertion: b"local-platform-prompt",
        },
    )?;
    if decision.is_approved() {
        Ok(())
    } else {
        Err(format!("platform biometric approval failed closed: {decision:?}").into())
    }
}

fn approval_challenge_from_proto(
    request: &proto::ApprovalRequestInfo,
) -> Result<hem_core::ApprovalChallenge, Box<dyn std::error::Error>> {
    let secret = request
        .secret
        .as_ref()
        .ok_or("approval request is missing secret reference")?;
    let scope = proto_scope_to_core(
        secret
            .scope
            .as_ref()
            .ok_or("approval request is missing secret scope")?,
    )?;
    let secret_version = normalize_optional_string(request.secret_version.clone());
    let requested_by = normalize_optional_string(request.requester_token_id.clone())
        .or_else(|| normalize_optional_string(request.requester_identity_id.clone()))
        .or_else(|| normalize_optional_string(request.requester_project.clone()))
        .ok_or("approval request is missing requester identity")?;
    let challenge = hem_core::ApprovalChallenge {
        request_id: request.request_id.clone(),
        action: request.action.clone(),
        secret_scope: scope,
        secret_name: secret.name.clone(),
        secret_version,
        requested_by,
    };
    challenge.validate()?;
    Ok(challenge)
}

fn proto_scope_to_core(
    scope: &ScopeSelector,
) -> Result<hem_core::SecretScope, Box<dyn std::error::Error>> {
    match SecretScope::try_from(scope.scope).unwrap_or(SecretScope::Unspecified) {
        SecretScope::Global => Ok(hem_core::SecretScope::Global),
        SecretScope::Project if !scope.project.trim().is_empty() => {
            Ok(hem_core::SecretScope::Project {
                project: scope.project.clone(),
            })
        }
        SecretScope::Project => Err("approval request project scope is missing project".into()),
        SecretScope::Identity if !scope.identity_id.trim().is_empty() => {
            Ok(hem_core::SecretScope::Identity {
                identity_id: scope.identity_id.clone(),
            })
        }
        SecretScope::Identity => {
            Err("approval request identity scope is missing identity id".into())
        }
        SecretScope::Unspecified => Err("approval request scope is unspecified".into()),
    }
}

fn secret_matches_query(secret: &proto::SecretInfo, query: &str) -> bool {
    let scope = secret
        .scope
        .as_ref()
        .map(format_scope)
        .unwrap_or_else(|| "unspecified".to_string());
    let name = secret.name.to_ascii_lowercase();
    let scope = scope.to_ascii_lowercase();
    let full = format!("{scope}/{name}");
    let description = secret.description.to_ascii_lowercase();
    let group = secret.group.to_ascii_lowercase();

    if has_wildcards(query) {
        return wildcard_match(query, name.as_str())
            || wildcard_match(query, scope.as_str())
            || wildcard_match(query, full.as_str())
            || wildcard_match(query, description.as_str())
            || wildcard_match(query, group.as_str());
    }

    name.contains(query)
        || scope.contains(query)
        || full.contains(query)
        || description.contains(query)
        || group.contains(query)
}

#[derive(Debug)]
struct SearchResults {
    matched: u32,
    shown: u32,
    sections: Vec<SearchSection>,
}

#[derive(Debug)]
struct SearchSection {
    heading: String,
    secrets: Vec<proto::SecretInfo>,
}

#[derive(Debug, Eq, PartialEq)]
struct SearchSortKey {
    scope_rank: u8,
    heading: String,
    secret_ref: String,
}

impl Ord for SearchSortKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.scope_rank
            .cmp(&other.scope_rank)
            .then_with(|| self.heading.cmp(&other.heading))
            .then_with(|| self.secret_ref.cmp(&other.secret_ref))
    }
}

impl PartialOrd for SearchSortKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn collect_search_results(
    secrets: Vec<proto::SecretInfo>,
    query: &str,
    display_limit: u32,
    group_projects: bool,
) -> SearchResults {
    let mut matched: Vec<proto::SecretInfo> = secrets
        .into_iter()
        .filter(|secret| secret_matches_query(secret, query))
        .collect();
    matched.sort_by_key(|secret| search_sort_key(secret, group_projects));

    let total = matched.len();
    let shown = if search_display_limit_reached(total as u32, display_limit) {
        display_limit as usize
    } else {
        total
    };

    let mut sections: Vec<SearchSection> = Vec::new();
    for secret in matched.into_iter().take(shown) {
        let heading = search_section_heading(&secret, group_projects);
        if let Some(section) = sections
            .last_mut()
            .filter(|section| section.heading == heading)
        {
            section.secrets.push(secret);
        } else {
            sections.push(SearchSection {
                heading,
                secrets: vec![secret],
            });
        }
    }

    SearchResults {
        matched: total as u32,
        shown: shown as u32,
        sections,
    }
}

fn search_sort_key(secret: &proto::SecretInfo, group_projects: bool) -> SearchSortKey {
    SearchSortKey {
        scope_rank: search_scope_rank(secret),
        heading: search_section_heading(secret, group_projects).to_ascii_lowercase(),
        secret_ref: search_secret_ref(secret).to_ascii_lowercase(),
    }
}

fn search_scope_rank(secret: &proto::SecretInfo) -> u8 {
    let Some(scope) = secret.scope.as_ref() else {
        return 3;
    };
    match SecretScope::try_from(scope.scope).unwrap_or(SecretScope::Unspecified) {
        SecretScope::Global => 0,
        SecretScope::Project => 1,
        SecretScope::Identity => 2,
        SecretScope::Unspecified => 3,
    }
}

fn search_section_heading(secret: &proto::SecretInfo, group_projects: bool) -> String {
    let Some(scope) = secret.scope.as_ref() else {
        return "unspecified".to_string();
    };
    match SecretScope::try_from(scope.scope).unwrap_or(SecretScope::Unspecified) {
        SecretScope::Global => "global".to_string(),
        SecretScope::Project if group_projects => format!("project/{}", scope.project),
        SecretScope::Project => "project".to_string(),
        SecretScope::Identity => "identity".to_string(),
        SecretScope::Unspecified => "unspecified".to_string(),
    }
}

fn search_secret_ref(secret: &proto::SecretInfo) -> String {
    let scope = secret
        .scope
        .as_ref()
        .map(format_scope)
        .unwrap_or_else(|| "unspecified".to_string());
    format!("{scope}/{}", secret.name)
}

fn search_request_limit() -> u32 {
    0
}

fn search_display_limit_reached(matched: u32, display_limit: u32) -> bool {
    display_limit > 0 && matched >= display_limit
}

fn search_truncation_summary(shown: u32, total: u32) -> Option<String> {
    if total > 0 && shown < total {
        Some(format!("showing {shown} of {total}"))
    } else {
        None
    }
}

fn has_wildcards(query: &str) -> bool {
    query.contains('*') || query.contains('?')
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();

    let mut p = 0_usize;
    let mut t = 0_usize;
    let mut last_star: Option<usize> = None;
    let mut last_star_match = 0_usize;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
            continue;
        }
        if p < pattern.len() && pattern[p] == b'*' {
            last_star = Some(p);
            p += 1;
            last_star_match = t;
            continue;
        }
        if let Some(star_index) = last_star {
            p = star_index + 1;
            last_star_match += 1;
            t = last_star_match;
            continue;
        }
        return false;
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }

    p == pattern.len()
}

fn color_output_enabled() -> bool {
    io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM")
            .map(|value| !value.trim().eq_ignore_ascii_case("dumb"))
            .unwrap_or(true)
}

fn colorize(enabled: bool, text: &str, ansi_code: &str) -> String {
    if !enabled {
        return text.to_string();
    }
    format!("\x1b[{ansi_code}m{text}\x1b[0m")
}

fn scope_color_code(scope: Option<&ScopeSelector>) -> &'static str {
    let value = scope
        .map(|item| item.scope)
        .unwrap_or(SecretScope::Global as i32);
    match value {
        v if v == SecretScope::Global as i32 => "34",
        v if v == SecretScope::Project as i32 => "36",
        v if v == SecretScope::Identity as i32 => "35",
        _ => "90",
    }
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default()
}

fn print_examples(format: ExamplesFormat) -> Result<(), Box<dyn std::error::Error>> {
    let body = render_examples(format)?;
    println!("{body}");
    Ok(())
}

fn print_usage() {
    println!("Hem usage");
    println!("  Shorthands: h health, i init, s set, g get, sc scan, l/ls search, ar archive, del/rm delete, ap approvals, ok approve, no deny, t token, ga grant-access, ra revoke-access, lg list-grants, au audit, ex export, im import, ro rotate, eg examples, u usage");
    println!();
    println!("  hem s openai-prod api_key=...");
    println!("  hem g openai-prod api_key");
    println!("  echo \"hello\" | hem sc");
    println!("  hem l 'project/*/openai-*'");
    println!("  hem ap");
    println!("  hem u");
}

fn print_search_secret(secret: &proto::SecretInfo, color_enabled: bool) {
    let scope_selector = secret.scope.as_ref();
    let scope = secret
        .scope
        .as_ref()
        .map(format_scope)
        .unwrap_or_else(|| "unspecified".to_string());
    let scope = colorize(
        color_enabled,
        scope.as_str(),
        scope_color_code(scope_selector),
    );
    let group = if secret.group.trim().is_empty() {
        "-"
    } else {
        secret.group.as_str()
    };
    let group = if group == "-" {
        colorize(color_enabled, group, "2")
    } else {
        colorize(color_enabled, group, "33")
    };
    let name = colorize(color_enabled, secret.name.as_str(), "1;32");
    let updated = colorize(color_enabled, secret.updated_at.as_str(), "2");
    println!("  {}/{} group={} updated={}", scope, name, group, updated);
    if !secret.description.trim().is_empty() {
        println!(
            "    {}",
            colorize(color_enabled, secret.description.trim(), "2")
        );
    }
}

fn print_kv(key: &str, value: impl std::fmt::Display) {
    println!(
        "{:<24} {}",
        colorize(color_output_enabled(), key, "1;34"),
        value
    );
}

fn print_table_header(columns: &[&str]) {
    println!(
        "{}",
        colorize(color_output_enabled(), columns.join("\t").as_str(), "1;36")
    );
}

fn render_examples(format: ExamplesFormat) -> Result<String, Box<dyn std::error::Error>> {
    match format {
        ExamplesFormat::Json => Ok(serde_json::to_string_pretty(&HemExamples::default())?),
        ExamplesFormat::Shell => Ok(render_examples_shell()),
    }
}

fn render_examples_shell() -> String {
    [
        "# hem examples (shell)",
        "# secret refs: <name> | global/<name> | project/<project>/<name> | identity/<identity_id>/<name>",
        "hem set openai-prod api_key=... model=gpt-4.1",
        "hem set openai-prod --interactive",
        "hem set openai-prod api_key=op://Personal/openai-prod/api_key",
        "hem set openai-prod --from-op-item op://Personal/openai-prod",
        "hem get openai-prod",
        "echo 'text to check' | hem scan",
        "echo 'text to check' | hem scan --quiet",
        "hem search 'project/*/openai-*'",
        "hem archive global/openai-prod",
        "# token flow",
        "hem token issue-service smi",
        "hem token issue-agent --identity-id agent-123 --project acme --scopes global,project,identity",
        "hem token list --token-type service",
        "hem token revoke <token-id>",
        "# grants + audit",
        "hem grant-access project/acme/openai-prod --grantee-scope global --grantee-id smi",
        "hem list-grants project/acme/openai-prod",
        "hem audit --limit 50",
        "# admin bundle/rotation",
        "hem export -o /tmp/hem-export.bin",
        "hem import -i /tmp/hem-export.bin --merge",
        "hem rotate",
        "# delete approval flow",
        "hem delete global/openai-prod",
        "hem approvals",
        "hem approve <request-id>",
        "hem delete global/openai-prod --approval-receipt <receipt>",
    ]
    .join("\n")
}

fn write_secure_json<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("tmp");
    let body = serde_json::to_vec_pretty(value)?;
    fs::write(temp.as_path(), body)?;
    fs::rename(temp.as_path(), path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn write_secure_bytes(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("tmp");
    fs::write(temp.as_path(), bytes)?;
    fs::rename(temp.as_path(), path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct ArchiveFile {
    version: String,
    archived_at_epoch_ms: u128,
    secret: ArchivedSecret,
}

#[derive(Debug, Serialize)]
struct ArchivedSecret {
    scope: String,
    name: String,
    description: String,
    requires_approval: bool,
    group: Option<String>,
    created_at: String,
    updated_at: String,
    created_by: String,
    last_accessed_at: Option<String>,
    last_accessed_by: Option<String>,
    values: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct ScanOutput {
    clean: bool,
    matches: Vec<ScanOutputMatch>,
    scanned_length: u32,
    secrets_checked: u32,
}

#[derive(Debug, Serialize)]
struct ScanOutputMatch {
    secret: String,
    key: String,
    offset: u32,
}

#[derive(Debug, Serialize)]
struct HemExamples {
    version: &'static str,
    generated_at_epoch_ms: u128,
    secret_ref_formats: Vec<&'static str>,
    wildcard_search: WildcardExamples,
    workflows: Vec<WorkflowExamples>,
    notes: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct WildcardExamples {
    syntax: Vec<&'static str>,
    examples: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct WorkflowExamples {
    name: &'static str,
    purpose: &'static str,
    commands: Vec<&'static str>,
}

impl Default for HemExamples {
    fn default() -> Self {
        Self {
            version: "hem-examples-v1",
            generated_at_epoch_ms: now_epoch_ms(),
            secret_ref_formats: vec![
                "<name> (global)",
                "global/<name>",
                "project/<project>/<name>",
                "identity/<identity_id>/<name>",
            ],
            wildcard_search: WildcardExamples {
                syntax: vec![
                    "* matches zero or more characters",
                    "? matches one character",
                ],
                examples: vec![
                    "hem search openai",
                    "hem search 'project/*/openai-*'",
                    "hem search 'identity/*/github'",
                ],
            },
            workflows: vec![
                WorkflowExamples {
                    name: "set_secret",
                    purpose: "create or update secret values",
                    commands: vec![
                        "hem set openai-prod api_key=... model=gpt-4.1",
                        "hem set project/acme/cloudflare token=...",
                        "hem set openai-prod --interactive",
                        "hem set openai-prod api_key=op://Personal/openai-prod/api_key",
                        "hem set openai-prod --from-op-item op://Personal/openai-prod",
                    ],
                },
                WorkflowExamples {
                    name: "get_secret",
                    purpose: "read values by key or full secret",
                    commands: vec![
                        "hem get openai-prod",
                        "hem get project/acme/cloudflare token",
                    ],
                },
                WorkflowExamples {
                    name: "scan_for_secret_leaks",
                    purpose: "scan stdin for leaked secret values",
                    commands: vec![
                        "echo 'text to check' | hem scan",
                        "echo 'text to check' | hem scan --quiet",
                        "echo 'text to check' | hem scan --scope project/acme --json",
                    ],
                },
                WorkflowExamples {
                    name: "archive_secret",
                    purpose: "write a local JSON archive",
                    commands: vec![
                        "hem archive global/openai-prod",
                        "hem archive project/acme/cloudflare -o /tmp/cloudflare.json",
                    ],
                },
                WorkflowExamples {
                    name: "token_lifecycle",
                    purpose: "issue, inspect, and revoke runtime tokens",
                    commands: vec![
                        "hem token issue-service smi",
                        "hem token issue-agent --identity-id agent-123 --project acme --scopes global,project,identity",
                        "hem token list --token-type service",
                        "hem token revoke <token-id>",
                    ],
                },
                WorkflowExamples {
                    name: "grants",
                    purpose: "allow scoped cross-scope reads",
                    commands: vec![
                        "hem grant-access project/acme/cloudflare --grantee-scope global --grantee-id smi",
                        "hem list-grants project/acme/cloudflare",
                        "hem revoke-access project/acme/cloudflare --grantee-scope global --grantee-id smi",
                    ],
                },
                WorkflowExamples {
                    name: "audit",
                    purpose: "inspect access and mutation history",
                    commands: vec![
                        "hem audit --limit 100",
                        "hem audit --scope project/acme --since 2026-02-21T00:00:00Z",
                    ],
                },
                WorkflowExamples {
                    name: "admin_export_import_rotate",
                    purpose: "backup/restore and key rotation",
                    commands: vec![
                        "hem export -o /tmp/hem-export.bin",
                        "hem import -i /tmp/hem-export.bin --merge",
                        "hem rotate",
                    ],
                },
                WorkflowExamples {
                    name: "delete_with_approval",
                    purpose: "request + approve + execute delete",
                    commands: vec![
                        "hem delete global/openai-prod",
                        "hem approvals",
                        "hem approve <request-id>",
                        "hem delete global/openai-prod --approval-receipt <receipt>",
                    ],
                },
            ],
            notes: vec![
                "quote wildcard patterns so shell does not expand '*' and '?'",
                "approve/deny require interactive human confirmation (legacy aliases: approve-delete/deny-delete)",
                "endpoint override: --endpoint or VALHALL_HEMD_ENDPOINT",
                "set values prefixed with op:// resolve through `op read` (1Password CLI)",
                "set --from-op-item imports all non-empty fields from a 1Password item",
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_matches_name_and_scope_and_group() {
        let secret = proto::SecretInfo {
            scope: Some(ScopeSelector {
                scope: SecretScope::Project as i32,
                project: "proj-a".to_string(),
                identity_id: String::new(),
            }),
            name: "openai-prod".to_string(),
            description: "OpenAI production key".to_string(),
            requires_approval: false,
            group: "llm".to_string(),
            created_at: String::new(),
            updated_at: String::new(),
            created_by: String::new(),
            last_accessed_at: String::new(),
            last_accessed_by: String::new(),
        };

        assert!(secret_matches_query(&secret, "openai"));
        assert!(secret_matches_query(&secret, "project/proj-a"));
        assert!(secret_matches_query(&secret, "llm"));
        assert!(!secret_matches_query(&secret, "anthropic"));
    }

    #[test]
    fn search_wildcards_match_expected_fields() {
        let secret = proto::SecretInfo {
            scope: Some(ScopeSelector {
                scope: SecretScope::Project as i32,
                project: "proj-a".to_string(),
                identity_id: String::new(),
            }),
            name: "openai-prod".to_string(),
            description: "OpenAI production key".to_string(),
            requires_approval: false,
            group: "llm".to_string(),
            created_at: String::new(),
            updated_at: String::new(),
            created_by: String::new(),
            last_accessed_at: String::new(),
            last_accessed_by: String::new(),
        };

        assert!(secret_matches_query(&secret, "openai-*"));
        assert!(secret_matches_query(&secret, "project/*/openai-*"));
        assert!(secret_matches_query(&secret, "*production*"));
        assert!(secret_matches_query(&secret, "o?enai-prod"));
        assert!(!secret_matches_query(&secret, "identity/*/openai-*"));
    }

    #[test]
    fn wildcard_match_handles_star_and_question_mark() {
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("abc*", "abcdef"));
        assert!(wildcard_match("ab?d", "abcd"));
        assert!(!wildcard_match("ab?d", "abxdz"));
        assert!(!wildcard_match("prod-*", "staging-key"));
    }

    #[test]
    fn search_request_limit_fetches_all_to_count_truncation() {
        assert_eq!(search_request_limit(), 0);
    }

    #[test]
    fn search_display_limit_is_applied_after_matching() {
        assert!(!search_display_limit_reached(24, 25));
        assert!(search_display_limit_reached(25, 25));
        assert!(!search_display_limit_reached(25, 0));
    }

    #[test]
    fn search_default_limit_is_100() {
        let cli = Cli::try_parse_from(["hem", "ls"]).expect("parse cli");
        let Commands::Search { limit, .. } = cli.command else {
            panic!("expected search command");
        };
        assert_eq!(limit, 100);
    }

    #[test]
    fn search_summary_reports_truncation_only_when_not_all_are_shown() {
        assert_eq!(
            search_truncation_summary(50, 75),
            Some("showing 50 of 75".to_string())
        );
        assert_eq!(search_truncation_summary(75, 75), None);
        assert_eq!(search_truncation_summary(0, 0), None);
    }

    #[test]
    fn search_group_projects_flag_is_parsed() {
        let cli = Cli::try_parse_from(["hem", "ls", "--group-projects"]).expect("parse cli");
        let Commands::Search { group_projects, .. } = cli.command else {
            panic!("expected search command");
        };
        assert!(group_projects);
    }

    #[test]
    fn search_group_projects_short_flag_is_parsed() {
        let cli = Cli::try_parse_from(["hem", "ls", "-p"]).expect("parse cli");
        let Commands::Search { group_projects, .. } = cli.command else {
            panic!("expected search command");
        };
        assert!(group_projects);
    }

    #[test]
    fn search_results_group_top_level_scopes_and_sort_refs() {
        let results = collect_search_results(
            vec![
                project_secret("zeta", "z-key"),
                global_secret("beta"),
                identity_secret("agent-b", "token"),
                project_secret("alpha", "a-key"),
                global_secret("alpha"),
            ],
            "*",
            0,
            false,
        );

        assert_eq!(results.matched, 5);
        assert_eq!(results.shown, 5);
        assert_search_sections(
            &results,
            &[
                ("global", &["global/alpha", "global/beta"]),
                ("project", &["project/alpha/a-key", "project/zeta/z-key"]),
                ("identity", &["identity/agent-b/token"]),
            ],
        );
    }

    #[test]
    fn search_results_can_group_each_project() {
        let results = collect_search_results(
            vec![
                project_secret("zeta", "z-key"),
                project_secret("alpha", "b-key"),
                project_secret("alpha", "a-key"),
            ],
            "*",
            0,
            true,
        );

        assert_search_sections(
            &results,
            &[
                (
                    "project/alpha",
                    &["project/alpha/a-key", "project/alpha/b-key"],
                ),
                ("project/zeta", &["project/zeta/z-key"]),
            ],
        );
    }

    #[test]
    fn normalize_query_rejects_empty() {
        let err = normalize_query("   ").expect_err("must reject empty");
        assert!(err.to_string().contains("query must not be empty"));
    }

    #[test]
    fn approval_state_label_maps_values() {
        assert_eq!(
            approval_state_label(proto::ApprovalState::Pending as i32),
            "pending"
        );
        assert_eq!(
            approval_state_label(proto::ApprovalState::Approved as i32),
            "approved"
        );
    }

    #[test]
    fn approval_challenge_from_proto_preserves_request_context_and_version() {
        let request = proto::ApprovalRequestInfo {
            request_id: "apr-test".to_string(),
            state: proto::ApprovalState::Pending as i32,
            secret: Some(SecretRef {
                scope: Some(ScopeSelector {
                    scope: SecretScope::Project as i32,
                    project: "valhall".to_string(),
                    identity_id: String::new(),
                }),
                name: "demo-secret".to_string(),
            }),
            requester_token_id: "agent-a".to_string(),
            requester_identity_id: String::new(),
            requester_project: String::new(),
            reason: "secret read requires master approval".to_string(),
            created_at: "2026-05-26T12:00:00Z".to_string(),
            resolved_at: String::new(),
            resolved_by: String::new(),
            resolve_message: String::new(),
            action: "get_secret".to_string(),
            secret_version: "version-1".to_string(),
        };

        let challenge = approval_challenge_from_proto(&request).expect("challenge");

        assert_eq!(challenge.request_id, "apr-test");
        assert_eq!(challenge.action, "get_secret");
        assert_eq!(
            challenge.secret_scope,
            hem_core::SecretScope::Project {
                project: "valhall".to_string()
            }
        );
        assert_eq!(challenge.secret_name, "demo-secret");
        assert_eq!(challenge.secret_version.as_deref(), Some("version-1"));
        assert_eq!(challenge.requested_by, "agent-a");
    }

    #[test]
    fn default_archive_path_contains_scope_and_name() {
        let path = default_archive_path("global", "openai-prod");
        let rendered = path.display().to_string();
        assert!(rendered.contains("global-openai-prod.json"));
    }

    #[test]
    fn default_export_path_uses_export_suffix() {
        let path = default_export_path();
        let rendered = path.display().to_string();
        assert!(rendered.contains("hem-export.bin"));
    }

    #[test]
    fn parse_secret_ref_unknown_prefix_has_actionable_hint() {
        let err = parse_secret_ref_or_global("tmp/codex-test")
            .expect_err("must reject unknown scope prefix");
        let message = err.to_string();
        assert!(message.contains("accepted formats"));
        assert!(message.contains("global/<name>"));
        assert!(message.contains("hem set my-secret key=value"));
    }

    #[test]
    fn examples_json_contains_delete_approval_flow() {
        let body = render_examples(ExamplesFormat::Json).expect("must render json examples");
        assert!(body.contains("\"version\": \"hem-examples-v1\""));
        assert!(body.contains("\"delete_with_approval\""));
        assert!(body.contains("\"scan_for_secret_leaks\""));
        assert!(body.contains("hem scan --quiet"));
        assert!(body.contains("hem approve <request-id>"));
        assert!(body.contains("\"grants\""));
        assert!(body.contains("\"audit\""));
    }

    #[test]
    fn token_arg_mappings_are_stable() {
        assert_eq!(
            token_scope_arg_to_proto(TokenScopeArg::Global),
            proto::SecretScope::Global as i32
        );
        assert_eq!(
            token_scope_arg_to_proto(TokenScopeArg::Project),
            proto::SecretScope::Project as i32
        );
        assert_eq!(
            token_type_arg_to_proto(TokenTypeArg::AgentRun),
            proto::TokenType::AgentRun as i32
        );
        assert_eq!(format_token_type(proto::TokenType::Service), "service");
    }

    #[test]
    fn parse_scope_selector_value_supports_expected_shapes() {
        let global = parse_scope_selector_value("global").expect("global");
        assert_eq!(global.scope, SecretScope::Global as i32);

        let project = parse_scope_selector_value("project/proj-a").expect("project");
        assert_eq!(project.scope, SecretScope::Project as i32);
        assert_eq!(project.project, "proj-a");

        let identity = parse_scope_selector_value("identity/agent-1").expect("identity");
        assert_eq!(identity.scope, SecretScope::Identity as i32);
        assert_eq!(identity.identity_id, "agent-1");
    }

    #[test]
    fn parse_scope_selector_value_rejects_invalid() {
        let err =
            parse_scope_selector_value("project/proj-a/extra").expect_err("must reject invalid");
        assert!(err
            .to_string()
            .contains("expected: global | project/<project> | identity/<identity_id>"));
    }

    #[test]
    fn parse_set_value_entry_supports_key_only_in_interactive_mode() {
        let (key, value) = parse_set_value_entry("api_key", true).expect("parse");
        assert_eq!(key, "api_key");
        assert!(value.is_none());
    }

    #[test]
    fn parse_set_value_entry_requires_equals_when_not_interactive() {
        let err = parse_set_value_entry("api_key", false).expect_err("must reject");
        assert!(err.to_string().contains("invalid key=value pair"));
    }

    #[test]
    fn resolve_value_source_with_reads_op_reference() {
        let value = resolve_value_source_with("op://vault/item/field".to_string(), |reference| {
            Ok(format!("resolved:{reference}"))
        })
        .expect("resolve");
        assert_eq!(value, "resolved:op://vault/item/field");
    }

    #[test]
    fn resolve_value_source_with_keeps_plain_values() {
        let value = resolve_value_source_with("plain-value".to_string(), |_reference| {
            Err("should not call op reader".into())
        })
        .expect("resolve");
        assert_eq!(value, "plain-value");
    }

    #[test]
    fn parse_op_item_locator_supports_op_reference() {
        let parsed = parse_op_item_locator("op://Personal/openai-prod").expect("parse");
        assert_eq!(parsed.vault.as_deref(), Some("Personal"));
        assert_eq!(parsed.item, "openai-prod");
    }

    #[test]
    fn parse_op_item_locator_rejects_field_references() {
        let err = parse_op_item_locator("op://Personal/openai-prod/api_key")
            .expect_err("must reject field refs for item import");
        assert!(err.to_string().contains("op://<vault>/<item>"));
    }

    #[test]
    fn parse_op_item_json_values_extracts_non_empty_fields() {
        let body = serde_json::json!({
            "fields": [
                {"id": "username", "value": "user-a"},
                {"id": "password", "value": "secret-a"},
                {"id": "unused", "value": null},
                {"id": "otp_seed", "value": 12345}
            ]
        })
        .to_string();

        let values = parse_op_item_json_values(body.as_str()).expect("parse op item");
        assert_eq!(values.len(), 3);
        assert!(values
            .iter()
            .any(|item| item.key == "username" && item.value == "user-a"));
        assert!(values
            .iter()
            .any(|item| item.key == "password" && item.value == "secret-a"));
        assert!(values
            .iter()
            .any(|item| item.key == "otp_seed" && item.value == "12345"));
    }

    #[test]
    fn merge_secret_values_overrides_matching_keys() {
        let merged = merge_secret_values(
            vec![SecretValue {
                key: "api_key".to_string(),
                value: "old".to_string(),
            }],
            vec![
                SecretValue {
                    key: "api_key".to_string(),
                    value: "new".to_string(),
                },
                SecretValue {
                    key: "region".to_string(),
                    value: "us".to_string(),
                },
            ],
        );
        assert_eq!(merged.len(), 2);
        assert!(merged
            .iter()
            .any(|item| item.key == "api_key" && item.value == "new"));
        assert!(merged
            .iter()
            .any(|item| item.key == "region" && item.value == "us"));
    }

    #[test]
    fn build_set_values_preserves_existing_keys_for_interactive_updates() {
        let merged = build_set_values(
            vec![
                SecretValue {
                    key: "api_key".to_string(),
                    value: "old".to_string(),
                },
                SecretValue {
                    key: "region".to_string(),
                    value: "eu".to_string(),
                },
            ],
            Vec::new(),
            vec![SecretValue {
                key: "api_key".to_string(),
                value: "new".to_string(),
            }],
        );
        assert_eq!(merged.len(), 2);
        assert!(merged
            .iter()
            .any(|item| item.key == "api_key" && item.value == "new"));
        assert!(merged
            .iter()
            .any(|item| item.key == "region" && item.value == "eu"));
    }

    #[test]
    fn secret_values_from_map_converts_all_entries() {
        let values = secret_values_from_map(HashMap::from([
            ("api_key".to_string(), "secret".to_string()),
            ("region".to_string(), "eu".to_string()),
        ]));
        assert_eq!(values.len(), 2);
        assert!(values
            .iter()
            .any(|item| item.key == "api_key" && item.value == "secret"));
        assert!(values
            .iter()
            .any(|item| item.key == "region" && item.value == "eu"));
    }

    #[test]
    fn required_secret_key_value_returns_value() {
        let secret = proto::SecretWithValues {
            info: None,
            values: HashMap::from([("api_key".to_string(), "secret-1".to_string())]),
        };
        let value = required_secret_key_value(&secret, "api_key").expect("key should exist");
        assert_eq!(value, "secret-1");
    }

    #[test]
    fn required_secret_key_value_errors_when_missing() {
        let secret = proto::SecretWithValues {
            info: None,
            values: HashMap::new(),
        };
        let err = required_secret_key_value(&secret, "api_key").expect_err("must reject");
        assert!(err
            .to_string()
            .contains("missing requested key 'api_key' in get response"));
    }

    #[test]
    fn scope_color_code_maps_known_scopes() {
        let global = ScopeSelector {
            scope: SecretScope::Global as i32,
            project: String::new(),
            identity_id: String::new(),
        };
        let project = ScopeSelector {
            scope: SecretScope::Project as i32,
            project: "proj-a".to_string(),
            identity_id: String::new(),
        };
        let identity = ScopeSelector {
            scope: SecretScope::Identity as i32,
            project: String::new(),
            identity_id: "agent-1".to_string(),
        };

        assert_eq!(scope_color_code(Some(&global)), "34");
        assert_eq!(scope_color_code(Some(&project)), "36");
        assert_eq!(scope_color_code(Some(&identity)), "35");
        assert_eq!(scope_color_code(None), "34");
    }

    #[test]
    fn colorize_disabled_returns_plain_text() {
        assert_eq!(colorize(false, "plain", "32"), "plain");
    }

    fn assert_search_sections(results: &SearchResults, expected: &[(&str, &[&str])]) {
        let actual: Vec<(String, Vec<String>)> = results
            .sections
            .iter()
            .map(|section| {
                (
                    section.heading.clone(),
                    section.secrets.iter().map(search_secret_ref).collect(),
                )
            })
            .collect();
        let expected: Vec<(String, Vec<String>)> = expected
            .iter()
            .map(|(heading, refs)| {
                (
                    (*heading).to_string(),
                    refs.iter().map(|value| (*value).to_string()).collect(),
                )
            })
            .collect();
        assert_eq!(actual, expected);
    }

    fn global_secret(name: &str) -> proto::SecretInfo {
        test_secret(
            ScopeSelector {
                scope: SecretScope::Global as i32,
                project: String::new(),
                identity_id: String::new(),
            },
            name,
        )
    }

    fn project_secret(project: &str, name: &str) -> proto::SecretInfo {
        test_secret(
            ScopeSelector {
                scope: SecretScope::Project as i32,
                project: project.to_string(),
                identity_id: String::new(),
            },
            name,
        )
    }

    fn identity_secret(identity_id: &str, name: &str) -> proto::SecretInfo {
        test_secret(
            ScopeSelector {
                scope: SecretScope::Identity as i32,
                project: String::new(),
                identity_id: identity_id.to_string(),
            },
            name,
        )
    }

    fn test_secret(scope: ScopeSelector, name: &str) -> proto::SecretInfo {
        proto::SecretInfo {
            scope: Some(scope),
            name: name.to_string(),
            description: String::new(),
            requires_approval: false,
            group: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
            created_by: String::new(),
            last_accessed_at: String::new(),
            last_accessed_by: String::new(),
        }
    }
}
