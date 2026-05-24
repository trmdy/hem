#![allow(clippy::large_enum_variant)]

use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    fs,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand, ValueEnum};
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
    ListPendingApprovalsRequest, ListSecretsRequest, ResolveApprovalRequest, RevokeAccessRequest,
    RevokeTokenRequest, RotateMasterKeyRequest, ScanForSecretsRequest, ScopeResolutionContext,
    ScopeSelector, SecretRef, SecretScope, SecretValue, SetSecretRequest,
};

const SECRET_REF_FORMATS: &str =
    "<name> (global), global/<name>, project/<project>/<name>, identity/<identity_id>/<name>";
const AUTHORIZATION_METADATA_KEY: &str = "authorization";
const DEFAULT_HEM_SUBDIR: &str = ".valhall/hem";
const DEFAULT_HEM_SYSTEM_DAEMONS_SUBDIR: &str = ".valhall/system-daemons/data/hem";
const OPERATOR_TOKEN_FILE: &str = "operator.token";
const DEFAULT_SCAN_MIN_VALUE_LENGTH: u32 = 8;
const DEFAULT_SEARCH_LIMIT: u32 = 50;

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
    #[command(about = "Issue/list/revoke Hem access tokens", visible_alias = "t")]
    Token {
        #[command(subcommand)]
        command: TokenCommands,
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
            actor,
            message,
        } => {
            confirm_human_approval(request_id.as_str(), true)?;
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
        Commands::Examples { .. } | Commands::Usage => {
            unreachable!("usage/examples command is handled before daemon connect")
        }
    }

    Ok(0)
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
    fn search_default_limit_is_50() {
        let cli = Cli::try_parse_from(["hem", "ls"]).expect("parse cli");
        let Commands::Search { limit, .. } = cli.command else {
            panic!("expected search command");
        };
        assert_eq!(limit, 50);
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
