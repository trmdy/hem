use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use tempfile::TempDir;
use tokio::time::sleep;
use tonic::{
    codegen::InterceptedService,
    metadata::MetadataValue,
    service::Interceptor,
    transport::{Channel, Endpoint},
    Code, Request,
};

pub mod proto {
    tonic::include_proto!("valhall.hem.v1");
}

use proto::{
    get_secret_request, get_secret_response, hem_runtime_client::HemRuntimeClient,
    ExportSecretsRequest, GetAuditLogRequest, GetSecretRequest, GrantAccessRequest, HealthRequest,
    ImportSecretsRequest, InitHemRequest, IssueAgentTokenRequest, IssueServiceTokenRequest,
    ListSecretsRequest, ResolveApprovalRequest, RevokeTokenRequest, RotateMasterKeyRequest,
    ScopeResolutionContext, ScopeSelector, SecretRef, SecretScope, SecretValue, SetSecretRequest,
};

type Client = HemRuntimeClient<InterceptedService<Channel, BearerAuthInterceptor>>;

#[derive(Clone, Debug)]
struct BearerAuthInterceptor {
    authorization: Option<MetadataValue<tonic::metadata::Ascii>>,
}

impl BearerAuthInterceptor {
    fn new(token: Option<&str>) -> Result<Self, Box<dyn std::error::Error>> {
        let authorization = token.map(|token| {
            let rendered = format!("Bearer {}", token.trim());
            MetadataValue::try_from(rendered.as_str())
        });
        Ok(Self {
            authorization: authorization.transpose()?,
        })
    }
}

impl Interceptor for BearerAuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, tonic::Status> {
        if let Some(header) = self.authorization.as_ref() {
            request
                .metadata_mut()
                .insert("authorization", header.clone());
        }
        Ok(request)
    }
}

struct TestDaemon {
    _data_dir: TempDir,
    child: Child,
    endpoint: String,
}

impl TestDaemon {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let data_dir = tempfile::tempdir()?;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        drop(listener);

        let bind = addr.to_string();
        let endpoint = format!("http://{bind}");

        let child = Command::new(env!("CARGO_BIN_EXE_hemd"))
            .arg("--bind")
            .arg(bind)
            .arg("--data-dir")
            .arg(data_dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let daemon = Self {
            _data_dir: data_dir,
            child,
            endpoint,
        };
        daemon.wait_until_ready().await?;
        Ok(daemon)
    }

    async fn wait_until_ready(&self) -> Result<(), Box<dyn std::error::Error>> {
        let started = Instant::now();
        loop {
            if started.elapsed() > Duration::from_secs(10) {
                return Err("hemd did not become ready within timeout".into());
            }
            if let Ok(mut client) = connect_client(self.endpoint.as_str(), None).await {
                if client.health(HealthRequest {}).await.is_ok() {
                    return Ok(());
                }
            }
            sleep(Duration::from_millis(75)).await;
        }
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn scope_global() -> ScopeSelector {
    ScopeSelector {
        scope: SecretScope::Global as i32,
        project: String::new(),
        identity_id: String::new(),
    }
}

fn scope_project(project: &str) -> ScopeSelector {
    ScopeSelector {
        scope: SecretScope::Project as i32,
        project: project.to_string(),
        identity_id: String::new(),
    }
}

fn secret_ref(scope: ScopeSelector, name: &str) -> SecretRef {
    SecretRef {
        scope: Some(scope),
        name: name.to_string(),
    }
}

async fn connect_client(
    endpoint: &str,
    token: Option<&str>,
) -> Result<Client, Box<dyn std::error::Error>> {
    let channel = Endpoint::from_shared(endpoint.to_string())?
        .connect()
        .await?;
    let interceptor = BearerAuthInterceptor::new(token)?;
    Ok(HemRuntimeClient::with_interceptor(channel, interceptor))
}

async fn set_secret(
    client: &mut Client,
    scope: ScopeSelector,
    name: &str,
    values: &[(&str, &str)],
    requires_approval: bool,
) -> Result<(), tonic::Status> {
    client
        .set_secret(SetSecretRequest {
            secret: Some(secret_ref(scope, name)),
            values: values
                .iter()
                .map(|(key, value)| SecretValue {
                    key: key.to_string(),
                    value: value.to_string(),
                })
                .collect(),
            description: String::new(),
            requires_approval,
            group: String::new(),
            actor: "itest".to_string(),
            approval_receipt: String::new(),
            reason: String::new(),
        })
        .await?;
    Ok(())
}

fn get_lookup_secret(scope: ScopeSelector, name: &str) -> get_secret_request::Lookup {
    get_secret_request::Lookup::Secret(secret_ref(scope, name))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_grants_and_approval_receipts_matrix() -> Result<(), Box<dyn std::error::Error>> {
    let daemon = TestDaemon::start().await?;

    let mut bootstrap = connect_client(daemon.endpoint.as_str(), None).await?;
    let init = bootstrap
        .init_hem(InitHemRequest { force: false })
        .await?
        .into_inner();
    assert!(init.initialized);
    assert!(!init.operator_token.trim().is_empty());

    let mut operator =
        connect_client(daemon.endpoint.as_str(), Some(init.operator_token.as_str())).await?;

    let unauth_list = bootstrap
        .list_secrets(ListSecretsRequest {
            scope: None,
            group: String::new(),
            prefix: String::new(),
            limit: 0,
        })
        .await
        .expect_err("list_secrets must require token");
    assert_eq!(unauth_list.code(), Code::Unauthenticated);

    set_secret(
        &mut operator,
        scope_global(),
        "global-openai",
        &[("api_key", "g-key")],
        false,
    )
    .await?;
    set_secret(
        &mut operator,
        scope_project("proj-a"),
        "project-deploy",
        &[("token", "p-key")],
        false,
    )
    .await?;
    set_secret(
        &mut operator,
        scope_global(),
        "global-approved-read",
        &[("token", "needs-approval")],
        true,
    )
    .await?;

    let service_issue = operator
        .issue_service_token(IssueServiceTokenRequest {
            service_name: "smi".to_string(),
            ttl_seconds: 0,
            issued_by: "itest".to_string(),
        })
        .await?
        .into_inner();
    let service_token = service_issue.token;
    let service_token_id = service_issue
        .info
        .as_ref()
        .map(|item| item.token_id.clone())
        .ok_or("missing token info for issued service token")?;
    assert!(!service_token.trim().is_empty());

    let mut service =
        connect_client(daemon.endpoint.as_str(), Some(service_token.as_str())).await?;

    let global_secret = service
        .get_secret(GetSecretRequest {
            lookup: Some(get_lookup_secret(scope_global(), "global-openai")),
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
    match global_secret.result {
        Some(get_secret_response::Result::Secret(secret)) => {
            assert_eq!(secret.values.get("api_key"), Some(&"g-key".to_string()));
        }
        _ => panic!("expected immediate global secret read"),
    }

    let before_grant = service
        .list_secrets(ListSecretsRequest {
            scope: None,
            group: String::new(),
            prefix: String::new(),
            limit: 0,
        })
        .await?
        .into_inner();
    assert!(before_grant
        .secrets
        .iter()
        .all(|item| item.name != "project-deploy"));

    let denied_project = service
        .get_secret(GetSecretRequest {
            lookup: Some(get_lookup_secret(scope_project("proj-a"), "project-deploy")),
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
        .await
        .expect_err("project secret should be denied before grant");
    assert_eq!(denied_project.code(), Code::PermissionDenied);

    operator
        .grant_access(GrantAccessRequest {
            secret: Some(secret_ref(scope_project("proj-a"), "project-deploy")),
            grantee_scope: Some(scope_global()),
            grantee_id: "smi".to_string(),
            actor: "itest".to_string(),
        })
        .await?;

    let granted_project = service
        .get_secret(GetSecretRequest {
            lookup: Some(get_lookup_secret(scope_project("proj-a"), "project-deploy")),
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
    match granted_project.result {
        Some(get_secret_response::Result::Secret(secret)) => {
            assert_eq!(secret.values.get("token"), Some(&"p-key".to_string()));
        }
        _ => panic!("expected project secret read to succeed after grant"),
    }

    let after_grant = service
        .list_secrets(ListSecretsRequest {
            scope: None,
            group: String::new(),
            prefix: String::new(),
            limit: 0,
        })
        .await?
        .into_inner();
    assert!(after_grant
        .secrets
        .iter()
        .any(|item| item.name == "project-deploy"));

    let pending = service
        .get_secret(GetSecretRequest {
            lookup: Some(get_lookup_secret(scope_global(), "global-approved-read")),
            context: Some(ScopeResolutionContext {
                identity_id: String::new(),
                project: String::new(),
            }),
            key: String::new(),
            async_read: false,
            wait_timeout_ms: 0,
            reason: "need token".to_string(),
            approval_receipt: String::new(),
        })
        .await?
        .into_inner();
    let request_id = match pending.result {
        Some(get_secret_response::Result::Pending(pending)) => pending.request_id,
        _ => panic!("expected pending approval response"),
    };

    let approved = operator
        .approve_access(ResolveApprovalRequest {
            request_id: request_id.clone(),
            actor: "human".to_string(),
            message: "approved".to_string(),
        })
        .await?
        .into_inner();
    assert!(!approved.approval_receipt.trim().is_empty());
    let receipt = approved.approval_receipt;

    let approved_get = service
        .get_secret(GetSecretRequest {
            lookup: Some(get_lookup_secret(scope_global(), "global-approved-read")),
            context: Some(ScopeResolutionContext {
                identity_id: String::new(),
                project: String::new(),
            }),
            key: String::new(),
            async_read: false,
            wait_timeout_ms: 0,
            reason: String::new(),
            approval_receipt: receipt.clone(),
        })
        .await?
        .into_inner();
    match approved_get.result {
        Some(get_secret_response::Result::Secret(secret)) => {
            assert_eq!(
                secret.values.get("token"),
                Some(&"needs-approval".to_string())
            );
        }
        _ => panic!("expected approved get to return secret"),
    }

    let reused_receipt = service
        .get_secret(GetSecretRequest {
            lookup: Some(get_lookup_secret(scope_global(), "global-approved-read")),
            context: Some(ScopeResolutionContext {
                identity_id: String::new(),
                project: String::new(),
            }),
            key: String::new(),
            async_read: false,
            wait_timeout_ms: 0,
            reason: String::new(),
            approval_receipt: receipt,
        })
        .await
        .expect_err("receipt reuse must fail");
    assert_eq!(reused_receipt.code(), Code::FailedPrecondition);

    let second_pending = service
        .get_secret(GetSecretRequest {
            lookup: Some(get_lookup_secret(scope_global(), "global-approved-read")),
            context: Some(ScopeResolutionContext {
                identity_id: String::new(),
                project: String::new(),
            }),
            key: String::new(),
            async_read: false,
            wait_timeout_ms: 0,
            reason: "need read again".to_string(),
            approval_receipt: String::new(),
        })
        .await?
        .into_inner();
    let request_id_2 = match second_pending.result {
        Some(get_secret_response::Result::Pending(pending)) => pending.request_id,
        _ => panic!("expected second pending approval"),
    };

    let second_receipt = operator
        .approve_access(ResolveApprovalRequest {
            request_id: request_id_2,
            actor: "human".to_string(),
            message: "approved".to_string(),
        })
        .await?
        .into_inner()
        .approval_receipt;

    let wrong_action = service
        .set_secret(SetSecretRequest {
            secret: Some(secret_ref(scope_global(), "global-approved-read")),
            values: vec![SecretValue {
                key: "token".to_string(),
                value: "new-value".to_string(),
            }],
            description: String::new(),
            requires_approval: true,
            group: String::new(),
            actor: "svc".to_string(),
            approval_receipt: second_receipt,
            reason: String::new(),
        })
        .await
        .expect_err("receipt should be bound to get_secret action");
    assert_eq!(wrong_action.code(), Code::PermissionDenied);

    let agent_issue = operator
        .issue_agent_token(IssueAgentTokenRequest {
            identity_id: "agent-1".to_string(),
            project: String::new(),
            scopes: vec![SecretScope::Global as i32],
            ttl_seconds: 300,
            issued_by_service: "itest".to_string(),
        })
        .await?
        .into_inner();
    let agent_token_id = agent_issue
        .info
        .as_ref()
        .map(|item| item.token_id.clone())
        .ok_or("missing token info for issued agent token")?;

    let revoked = operator
        .revoke_token(RevokeTokenRequest {
            token_id: service_token_id.clone(),
            actor: "itest".to_string(),
        })
        .await?
        .into_inner();
    assert!(revoked.revoked);

    let audit = operator
        .get_audit_log(GetAuditLogRequest {
            scope: None,
            since: String::new(),
            until: String::new(),
            limit: 200,
        })
        .await?
        .into_inner();
    assert!(audit
        .entries
        .iter()
        .any(|item| item.action == "grant_access"));
    assert!(audit
        .entries
        .iter()
        .any(|item| item.action == "get_secret" && item.result == "pending_approval"));
    assert!(audit.entries.iter().any(|item| {
        item.action == "issue_service_token" && item.details.contains(service_token_id.as_str())
    }));
    assert!(audit.entries.iter().any(|item| {
        item.action == "issue_agent_token" && item.details.contains(agent_token_id.as_str())
    }));
    assert!(audit.entries.iter().any(|item| {
        item.action == "revoke_token" && item.details.contains(service_token_id.as_str())
    }));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_export_import_rotate_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let daemon = TestDaemon::start().await?;

    let mut bootstrap = connect_client(daemon.endpoint.as_str(), None).await?;
    let init = bootstrap
        .init_hem(InitHemRequest { force: false })
        .await?
        .into_inner();
    assert!(init.initialized);
    assert!(!init.operator_token.trim().is_empty());

    let mut operator =
        connect_client(daemon.endpoint.as_str(), Some(init.operator_token.as_str())).await?;
    set_secret(
        &mut operator,
        scope_global(),
        "export-me",
        &[("api_key", "secret-1"), ("org", "acme")],
        false,
    )
    .await?;

    let exported = operator
        .export_secrets(ExportSecretsRequest { scope: None })
        .await?
        .into_inner();
    assert!(!exported.encrypted_bundle.is_empty());

    set_secret(
        &mut operator,
        scope_global(),
        "export-me",
        &[("api_key", "changed"), ("org", "updated")],
        false,
    )
    .await?;

    let imported = operator
        .import_secrets(ImportSecretsRequest {
            encrypted_bundle: exported.encrypted_bundle.clone(),
            merge: false,
            actor: "itest".to_string(),
        })
        .await?
        .into_inner();
    assert_eq!(imported.imported_secret_count, 1);

    let restored = operator
        .get_secret(GetSecretRequest {
            lookup: Some(get_lookup_secret(scope_global(), "export-me")),
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
    match restored.result {
        Some(get_secret_response::Result::Secret(secret)) => {
            assert_eq!(secret.values.get("api_key"), Some(&"secret-1".to_string()));
            assert_eq!(secret.values.get("org"), Some(&"acme".to_string()));
        }
        _ => panic!("expected restored secret after import"),
    }

    let rotated = operator
        .rotate_master_key(RotateMasterKeyRequest {
            actor: "itest".to_string(),
        })
        .await?
        .into_inner();
    assert!(!rotated.new_key_id.trim().is_empty());
    assert!(rotated.rotated_secret_count >= 1);

    Ok(())
}
