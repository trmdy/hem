use std::{collections::HashMap, env, fs, path::Path, time::Duration};

use serde::{Deserialize, Serialize};

use crate::error::{MeshError, Result};

const DEFAULT_NATS_URL: &str = "nats://127.0.0.1:4222";
const DEFAULT_RPC_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_CONNECT_MAX_RETRIES: u32 = 8;
const DEFAULT_CONNECT_INITIAL_BACKOFF_MS: u64 = 200;
const DEFAULT_CONNECT_MAX_BACKOFF_MS: u64 = 5_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct MeshConfig {
    pub nats_url: String,
    pub node_id: String,
    pub service_endpoints: HashMap<String, String>,
    pub rpc_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub connect_max_retries: u32,
    pub connect_initial_backoff_ms: u64,
    pub connect_max_backoff_ms: u64,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            nats_url: DEFAULT_NATS_URL.to_string(),
            node_id: "local".to_string(),
            service_endpoints: HashMap::new(),
            rpc_timeout_ms: DEFAULT_RPC_TIMEOUT_MS,
            request_timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
            connect_max_retries: DEFAULT_CONNECT_MAX_RETRIES,
            connect_initial_backoff_ms: DEFAULT_CONNECT_INITIAL_BACKOFF_MS,
            connect_max_backoff_ms: DEFAULT_CONNECT_MAX_BACKOFF_MS,
        }
    }
}

impl MeshConfig {
    pub fn from_env() -> Result<Self> {
        let mut config = Self::default();
        config.apply_env_overrides(env::vars())?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)?;
        let config = match detect_format(path) {
            ConfigFormat::Json => serde_json::from_str::<MeshConfig>(&content)?,
            ConfigFormat::Toml => toml::from_str::<MeshConfig>(&content)?,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn from_file_with_env(path: impl AsRef<Path>) -> Result<Self> {
        let mut config = Self::from_file(path)?;
        config.apply_env_overrides(env::vars())?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.nats_url.trim().is_empty() {
            return Err(MeshError::Config("nats_url must not be empty".to_string()));
        }
        if self.node_id.trim().is_empty() {
            return Err(MeshError::Config("node_id must not be empty".to_string()));
        }
        if self.rpc_timeout_ms == 0 {
            return Err(MeshError::Config(
                "rpc_timeout_ms must be greater than 0".to_string(),
            ));
        }
        if self.request_timeout_ms == 0 {
            return Err(MeshError::Config(
                "request_timeout_ms must be greater than 0".to_string(),
            ));
        }
        if self.connect_initial_backoff_ms == 0 {
            return Err(MeshError::Config(
                "connect_initial_backoff_ms must be greater than 0".to_string(),
            ));
        }
        if self.connect_max_backoff_ms == 0 {
            return Err(MeshError::Config(
                "connect_max_backoff_ms must be greater than 0".to_string(),
            ));
        }
        if self.connect_initial_backoff_ms > self.connect_max_backoff_ms {
            return Err(MeshError::Config(
                "connect_initial_backoff_ms must be <= connect_max_backoff_ms".to_string(),
            ));
        }

        for (service, endpoint) in &self.service_endpoints {
            if service.trim().is_empty() {
                return Err(MeshError::Config(
                    "service_endpoints contains empty service key".to_string(),
                ));
            }
            if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
                return Err(MeshError::Config(format!(
                    "invalid gRPC endpoint for service '{service}': endpoint must start with http:// or https://"
                )));
            }
            tonic::transport::Endpoint::from_shared(endpoint.clone()).map_err(|err| {
                MeshError::Config(format!(
                    "invalid gRPC endpoint for service '{service}': {err}"
                ))
            })?;
        }

        Ok(())
    }

    pub fn rpc_timeout(&self) -> Duration {
        Duration::from_millis(self.rpc_timeout_ms)
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }

    fn apply_env_overrides(
        &mut self,
        vars: impl IntoIterator<Item = (String, String)>,
    ) -> Result<()> {
        for (key, value) in vars {
            match key.as_str() {
                "VALHALL_NET_NATS_URL" => self.nats_url = value,
                "VALHALL_NET_NODE_ID" => self.node_id = value,
                "VALHALL_NET_RPC_TIMEOUT_MS" => {
                    self.rpc_timeout_ms = parse_u64_env(&key, &value)?;
                }
                "VALHALL_NET_REQUEST_TIMEOUT_MS" => {
                    self.request_timeout_ms = parse_u64_env(&key, &value)?;
                }
                "VALHALL_NET_CONNECT_MAX_RETRIES" => {
                    self.connect_max_retries = parse_u32_env(&key, &value)?;
                }
                "VALHALL_NET_CONNECT_INITIAL_BACKOFF_MS" => {
                    self.connect_initial_backoff_ms = parse_u64_env(&key, &value)?;
                }
                "VALHALL_NET_CONNECT_MAX_BACKOFF_MS" => {
                    self.connect_max_backoff_ms = parse_u64_env(&key, &value)?;
                }
                "VALHALL_NET_SERVICE_ENDPOINTS_JSON" => {
                    let parsed = serde_json::from_str::<HashMap<String, String>>(&value)?;
                    self.service_endpoints.extend(parsed);
                }
                _ => {
                    if let Some(service) = key.strip_prefix("VALHALL_NET_SERVICE_ENDPOINT__") {
                        let service = service.trim().to_ascii_lowercase();
                        if service.is_empty() {
                            return Err(MeshError::Config(format!(
                                "{key} has empty service suffix"
                            )));
                        }
                        self.service_endpoints.insert(service, value);
                    }
                }
            }
        }
        Ok(())
    }
}

fn parse_u64_env(key: &str, value: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|err| MeshError::Config(format!("invalid value for {key}: {err}")))
}

fn parse_u32_env(key: &str, value: &str) -> Result<u32> {
    value
        .parse::<u32>()
        .map_err(|err| MeshError::Config(format!("invalid value for {key}: {err}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigFormat {
    Json,
    Toml,
}

fn detect_format(path: &Path) -> ConfigFormat {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => ConfigFormat::Json,
        _ => ConfigFormat::Toml,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec_vars(input: &[(&str, &str)]) -> Vec<(String, String)> {
        input
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn write_temp(path: &Path, data: &str) {
        fs::write(path, data).expect("write temp file");
    }

    #[test]
    fn default_config_is_valid() {
        let config = MeshConfig::default();
        config.validate().expect("default config should be valid");
    }

    #[test]
    fn can_load_from_toml_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("mesh.toml");
        write_temp(
            &path,
            r#"
nats_url = "nats://10.0.0.2:4222"
node_id = "node-a"
rpc_timeout_ms = 3000
request_timeout_ms = 4000
connect_max_retries = 5
connect_initial_backoff_ms = 200
connect_max_backoff_ms = 1000

[service_endpoints]
smi = "http://127.0.0.1:7001"
"#,
        );

        let config = MeshConfig::from_file(path).expect("load from toml");
        assert_eq!(config.node_id, "node-a");
        assert_eq!(
            config.service_endpoints.get("smi"),
            Some(&"http://127.0.0.1:7001".to_string())
        );
    }

    #[test]
    fn can_load_from_json_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("mesh.json");
        write_temp(
            &path,
            r#"
{
  "nats_url": "nats://10.0.0.3:4222",
  "node_id": "node-b",
  "rpc_timeout_ms": 3000,
  "request_timeout_ms": 4000,
  "connect_max_retries": 5,
  "connect_initial_backoff_ms": 200,
  "connect_max_backoff_ms": 1000,
  "service_endpoints": {
    "bod": "http://127.0.0.1:7002"
  }
}
"#,
        );

        let config = MeshConfig::from_file(path).expect("load from json");
        assert_eq!(config.node_id, "node-b");
        assert_eq!(
            config.service_endpoints.get("bod"),
            Some(&"http://127.0.0.1:7002".to_string())
        );
    }

    #[test]
    fn env_overrides_file_values() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("mesh.toml");
        write_temp(
            &path,
            r#"
nats_url = "nats://10.0.0.2:4222"
node_id = "node-a"
rpc_timeout_ms = 3000
request_timeout_ms = 4000
connect_max_retries = 5
connect_initial_backoff_ms = 200
connect_max_backoff_ms = 1000
"#,
        );

        let mut config = MeshConfig::from_file(&path).expect("load from file");
        config
            .apply_env_overrides(vec_vars(&[
                ("VALHALL_NET_NODE_ID", "node-override"),
                ("VALHALL_NET_RPC_TIMEOUT_MS", "9000"),
            ]))
            .expect("apply env overrides");
        config.validate().expect("validate overridden config");

        assert_eq!(config.node_id, "node-override");
        assert_eq!(config.rpc_timeout_ms, 9000);
    }

    #[test]
    fn endpoint_env_key_is_supported() {
        let mut config = MeshConfig::default();
        config
            .apply_env_overrides(vec_vars(&[(
                "VALHALL_NET_SERVICE_ENDPOINT__SMID",
                "http://127.0.0.1:7100",
            )]))
            .expect("apply endpoint env override");

        assert_eq!(
            config.service_endpoints.get("smid"),
            Some(&"http://127.0.0.1:7100".to_string())
        );
    }

    #[test]
    fn rejects_invalid_endpoint() {
        let mut config = MeshConfig::default();
        config
            .service_endpoints
            .insert("smi".to_string(), "not-a-uri".to_string());
        let err = config.validate().expect_err("invalid endpoint should fail");
        assert!(matches!(err, MeshError::Config(_)));
    }

    #[test]
    fn rejects_invalid_numeric_env_override() {
        let mut config = MeshConfig::default();
        let err = config
            .apply_env_overrides(vec_vars(&[("VALHALL_NET_RPC_TIMEOUT_MS", "oops")]))
            .expect_err("invalid integer env should fail");
        assert!(matches!(err, MeshError::Config(_)));
    }
}
