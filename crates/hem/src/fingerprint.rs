//! Caller fingerprinting for audit attribution (docs/1022, phase 2).
//!
//! Classifies the current invocation as `human`, `agent:<name>`, or `unknown`
//! from three signals: process ancestry, environment marker names, and TTY
//! status. The result is self-reported evidence for the daemon's audit log —
//! attribution hygiene, not adversarial security.
//!
//! Classification is positive-evidence-only: absence of a TTY never counts as
//! agent evidence (cron/launchd/scripts must classify `unknown`, which is
//! always allowed), and weak markers (env prefix families like `CODEX_*` that
//! users may export globally for other reasons) never classify by themselves.

use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::process::Command;

pub const HEM_CALLER_ENV: &str = "HEM_CALLER";
pub const HEM_AGENT_SESSION_ENV: &str = "HEM_AGENT_SESSION";
pub const HEM_ALLOW_UNATTRIBUTED_ENV: &str = "HEM_ALLOW_UNATTRIBUTED";

const MAX_ANCESTOR_HOPS: usize = 12;
const MAX_LABEL_LEN: usize = 64;

struct AgentSignature {
    name: &'static str,
    /// Process basenames that identify the agent when found in the ancestor chain.
    ancestors: &'static [&'static str],
    /// Env var names only ever set inside the agent's session (strong evidence).
    env_strong: &'static [&'static str],
    /// Env name prefixes belonging to the agent's family. Weak evidence: users
    /// may export e.g. CODEX_API_KEY globally, so these are recorded as
    /// markers but never classify on their own.
    env_weak_prefixes: &'static [&'static str],
}

const SIGNATURES: &[AgentSignature] = &[
    AgentSignature {
        name: "claude-code",
        ancestors: &["claude"],
        env_strong: &[
            "CLAUDECODE",
            "CLAUDE_CODE_SESSION_ID",
            "CLAUDE_CODE_ENTRYPOINT",
        ],
        env_weak_prefixes: &["CLAUDE_CODE_", "CLAUDE_"],
    },
    AgentSignature {
        name: "codex",
        ancestors: &["codex"],
        env_strong: &["CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED"],
        env_weak_prefixes: &["CODEX_"],
    },
    AgentSignature {
        name: "cursor",
        ancestors: &["cursor-agent"],
        env_strong: &["CURSOR_AGENT"],
        env_weak_prefixes: &["CURSOR_"],
    },
    AgentSignature {
        name: "grok",
        ancestors: &["grok"],
        env_strong: &["GROK_AGENT"],
        env_weak_prefixes: &["GROK_"],
    },
    AgentSignature {
        name: "gemini",
        ancestors: &["gemini"],
        env_strong: &[],
        env_weak_prefixes: &["GEMINI_CLI"],
    },
    AgentSignature {
        name: "amp",
        ancestors: &["amp"],
        env_strong: &["AMP_CURRENT_THREAD_ID"],
        env_weak_prefixes: &["AMP_"],
    },
    AgentSignature {
        name: "hive",
        ancestors: &[],
        env_strong: &["SMI_HEM_IDENTITY"],
        env_weak_prefixes: &["SMI_HEM_"],
    },
];

/// Env var names that suggest *some* agent without identifying which (weak).
const GENERIC_AGENT_ENV: &[&str] = &["AGENT", "AI_AGENT"];

/// Session-correlation env vars, in priority order.
const SESSION_ENV: &[&str] = &[
    HEM_AGENT_SESSION_ENV,
    "CLAUDE_CODE_SESSION_ID",
    "AMP_CURRENT_THREAD_ID",
];

/// Raw signals gathered from the environment; separated from classification
/// so the decision logic is pure and testable.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    /// Names of relevant env vars that are present (never values).
    pub env_names: Vec<String>,
    /// Value of the generic AGENT var, used only for equality against known
    /// agent names (e.g. AGENT=amp).
    pub agent_env_value: Option<String>,
    pub hem_caller: Option<String>,
    /// Ancestor process basenames, nearest (parent) first.
    pub ancestors: Vec<String>,
    pub stderr_tty: bool,
    pub session: Option<String>,
    pub allow_unattributed: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CallerFingerprint {
    pub classification: String,
    pub markers: Vec<String>,
    /// Subset of markers sent in the metadata header: strong evidence when
    /// any exists, else a capped set of weak markers. Keeps the header well
    /// under the daemon's 256-char metadata value cap.
    #[serde(skip)]
    header_markers: Vec<String>,
    pub tty: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// HEM_CALLER label, forwarded as x-hem-client-context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    pub allow_unattributed: bool,
    pub ancestors: Vec<String>,
}

pub fn collect() -> CallerFingerprint {
    classify(gather_evidence())
}

fn gather_evidence() -> Evidence {
    let mut env_names = Vec::new();
    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy().into_owned();
        let relevant = GENERIC_AGENT_ENV.contains(&name.as_str())
            || SIGNATURES.iter().any(|sig| {
                sig.env_strong.contains(&name.as_str())
                    || sig
                        .env_weak_prefixes
                        .iter()
                        .any(|prefix| name.starts_with(prefix))
            });
        if relevant {
            env_names.push(name);
        }
    }
    env_names.sort();

    Evidence {
        env_names,
        agent_env_value: std::env::var("AGENT").ok(),
        hem_caller: non_empty_env(HEM_CALLER_ENV),
        ancestors: ancestor_basenames(),
        stderr_tty: std::io::stderr().is_terminal(),
        session: SESSION_ENV.iter().find_map(|name| non_empty_env(name)),
        allow_unattributed: matches!(
            std::env::var(HEM_ALLOW_UNATTRIBUTED_ENV).ok().as_deref(),
            Some("1") | Some("true")
        ),
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    let value = std::env::var(name).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Walk the process ancestry via a single `ps` snapshot. Returns basenames,
/// nearest first. Best-effort: any failure returns an empty list.
fn ancestor_basenames() -> Vec<String> {
    let Ok(output) = Command::new("ps")
        .args(["-axo", "pid=,ppid=,comm="])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let table = String::from_utf8_lossy(&output.stdout);
    let mut procs: HashMap<u32, (u32, String)> = HashMap::new();
    for line in table.lines() {
        let mut parts = line.split_whitespace();
        let (Some(pid), Some(ppid)) = (parts.next(), parts.next()) else {
            continue;
        };
        let (Ok(pid), Ok(ppid)) = (pid.parse::<u32>(), ppid.parse::<u32>()) else {
            continue;
        };
        let comm = parts.collect::<Vec<_>>().join(" ");
        procs.insert(pid, (ppid, comm));
    }

    let mut ancestors = Vec::new();
    let mut seen = HashSet::new();
    let mut pid = std::os::unix::process::parent_id();
    while pid > 1 && ancestors.len() < MAX_ANCESTOR_HOPS && seen.insert(pid) {
        let Some((ppid, comm)) = procs.get(&pid) else {
            break;
        };
        let basename = comm
            .rsplit('/')
            .next()
            .unwrap_or(comm.as_str())
            .trim()
            .to_string();
        if !basename.is_empty() {
            ancestors.push(basename);
        }
        pid = *ppid;
    }
    ancestors
}

pub fn classify(evidence: Evidence) -> CallerFingerprint {
    let mut strong_markers = Vec::new();
    let mut weak_markers = Vec::new();
    let mut strong: Vec<&'static str> = Vec::new();

    // Ancestry evidence, nearest ancestor first so the closest agent wins.
    for ancestor in &evidence.ancestors {
        for sig in SIGNATURES {
            if sig.ancestors.contains(&ancestor.as_str()) {
                strong_markers.push(format!("ancestor:{ancestor}"));
                if !strong.contains(&sig.name) {
                    strong.push(sig.name);
                }
            }
        }
    }

    for name in &evidence.env_names {
        for sig in SIGNATURES {
            if sig.env_strong.contains(&name.as_str()) {
                strong_markers.push(format!("env:{name}"));
                if !strong.contains(&sig.name) {
                    strong.push(sig.name);
                }
            } else if sig
                .env_weak_prefixes
                .iter()
                .any(|prefix| name.starts_with(prefix))
            {
                weak_markers.push(format!("env:{name}"));
            }
        }
        if GENERIC_AGENT_ENV.contains(&name.as_str()) {
            weak_markers.push(format!("env:{name}"));
        }
    }

    // AGENT=<known-name> is strong self-identification (e.g. AGENT=amp).
    if let Some(value) = evidence.agent_env_value.as_deref() {
        let value = value.trim();
        if SIGNATURES.iter().any(|sig| sig.name == value) && !strong.contains(&value) {
            strong_markers.push(format!("env:AGENT={value}"));
            if let Some(sig) = SIGNATURES.iter().find(|sig| sig.name == value) {
                strong.push(sig.name);
            }
        }
    }

    strong_markers.sort();
    strong_markers.dedup();
    weak_markers.sort();
    weak_markers.dedup();
    let weak = !weak_markers.is_empty();

    const MAX_HEADER_MARKERS: usize = 6;
    let header_markers = if strong_markers.is_empty() {
        weak_markers
            .iter()
            .take(MAX_HEADER_MARKERS)
            .cloned()
            .collect()
    } else {
        strong_markers
            .iter()
            .take(MAX_HEADER_MARKERS)
            .cloned()
            .collect()
    };

    let mut markers = strong_markers;
    markers.extend(weak_markers);
    markers.sort();
    markers.dedup();

    let classification = if let Some(caller) = evidence.hem_caller.as_deref() {
        let label = sanitize_label(caller);
        if label == "human" {
            "human".to_string()
        } else {
            format!("agent:{label}")
        }
    } else if let Some(name) = strong.first() {
        format!("agent:{name}")
    } else if weak {
        "unknown".to_string()
    } else if evidence.stderr_tty {
        "human".to_string()
    } else {
        "unknown".to_string()
    };

    CallerFingerprint {
        classification,
        markers,
        header_markers,
        tty: evidence.stderr_tty,
        session: evidence.session.as_deref().map(sanitize_label),
        context: evidence.hem_caller.clone(),
        allow_unattributed: evidence.allow_unattributed,
        ancestors: evidence.ancestors,
    }
}

/// Keep labels safe for metadata and log parsing: ascii graphic minus the
/// fingerprint delimiters, capped length.
fn sanitize_label(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_graphic() && !matches!(c, ';' | ',' | '='))
        .take(MAX_LABEL_LEN)
        .collect()
}

impl CallerFingerprint {
    /// Render the x-hem-caller-fingerprint metadata value, e.g.
    /// `classification=agent:claude-code;tty=false;session=abc;markers=ancestor:claude,env:CLAUDECODE`.
    ///
    /// Fixed-size fields come first and markers last, so the daemon's
    /// metadata length cap can only ever truncate marker detail.
    pub fn header_value(&self) -> String {
        let mut parts = vec![
            format!("classification={}", self.classification),
            format!("tty={}", self.tty),
        ];
        if let Some(session) = self.session.as_deref() {
            parts.push(format!("session={session}"));
        }
        if self.allow_unattributed {
            parts.push("override=allow-unattributed".to_string());
        }
        if !self.header_markers.is_empty() {
            let markers = self
                .header_markers
                .iter()
                .map(|marker| sanitize_label(marker))
                .collect::<Vec<_>>()
                .join(",");
            parts.push(format!("markers={markers}"));
        }
        parts.join(";")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_evidence() -> Evidence {
        Evidence::default()
    }

    #[test]
    fn interactive_human_with_no_markers_classifies_human() {
        let fp = classify(Evidence {
            stderr_tty: true,
            ancestors: vec!["zsh".to_string(), "login".to_string(), "tmux".to_string()],
            ..base_evidence()
        });
        assert_eq!(fp.classification, "human");
        assert!(fp.markers.is_empty());
    }

    #[test]
    fn no_tty_without_markers_is_unknown_not_agent() {
        // cron/launchd/scripts: positive-evidence rule.
        let fp = classify(Evidence {
            stderr_tty: false,
            ancestors: vec!["bash".to_string(), "launchd".to_string()],
            ..base_evidence()
        });
        assert_eq!(fp.classification, "unknown");
    }

    #[test]
    fn claude_ancestry_and_env_classify_claude_code() {
        let fp = classify(Evidence {
            env_names: vec![
                "CLAUDECODE".to_string(),
                "CLAUDE_CODE_SESSION_ID".to_string(),
            ],
            ancestors: vec!["zsh".to_string(), "claude".to_string(), "node".to_string()],
            session: Some("sess-123".to_string()),
            ..base_evidence()
        });
        assert_eq!(fp.classification, "agent:claude-code");
        assert!(fp.markers.contains(&"ancestor:claude".to_string()));
        assert!(fp.markers.contains(&"env:CLAUDECODE".to_string()));
        assert_eq!(fp.session.as_deref(), Some("sess-123"));
    }

    #[test]
    fn ancestry_alone_is_sufficient_strong_evidence() {
        // env -i strips markers; the ancestor walk still catches it.
        let fp = classify(Evidence {
            ancestors: vec!["sh".to_string(), "codex".to_string()],
            ..base_evidence()
        });
        assert_eq!(fp.classification, "agent:codex");
    }

    #[test]
    fn weak_prefix_env_alone_never_classifies_agent() {
        // A user exporting CODEX_API_KEY globally must not be blocked at a
        // real terminal: weak markers are recorded but classification stays
        // out of agent:* (never-falter rule).
        let fp = classify(Evidence {
            env_names: vec!["CODEX_API_KEY".to_string()],
            stderr_tty: true,
            ..base_evidence()
        });
        assert_eq!(fp.classification, "unknown");
        assert!(fp.markers.contains(&"env:CODEX_API_KEY".to_string()));
    }

    #[test]
    fn generic_agent_env_is_weak_unknown() {
        let fp = classify(Evidence {
            env_names: vec!["AI_AGENT".to_string()],
            agent_env_value: None,
            stderr_tty: false,
            ..base_evidence()
        });
        assert_eq!(fp.classification, "unknown");
    }

    #[test]
    fn agent_env_value_matching_known_name_is_strong() {
        let fp = classify(Evidence {
            env_names: vec!["AGENT".to_string()],
            agent_env_value: Some("amp".to_string()),
            ..base_evidence()
        });
        assert_eq!(fp.classification, "agent:amp");
    }

    #[test]
    fn hem_caller_overrides_detection() {
        let fp = classify(Evidence {
            hem_caller: Some("hermes-mcp".to_string()),
            ancestors: vec!["claude".to_string()],
            ..base_evidence()
        });
        assert_eq!(fp.classification, "agent:hermes-mcp");
        // Detection evidence is still recorded alongside the label.
        assert!(fp.markers.contains(&"ancestor:claude".to_string()));
    }

    #[test]
    fn nearest_agent_ancestor_wins() {
        // hem under codex under claude (nested agents): the closest wins.
        let fp = classify(Evidence {
            ancestors: vec![
                "zsh".to_string(),
                "codex".to_string(),
                "zsh".to_string(),
                "claude".to_string(),
            ],
            ..base_evidence()
        });
        assert_eq!(fp.classification, "agent:codex");
    }

    #[test]
    fn header_value_round_trips_expected_shape() {
        let fp = classify(Evidence {
            env_names: vec!["CLAUDECODE".to_string()],
            ancestors: vec!["claude".to_string()],
            session: Some("s1".to_string()),
            allow_unattributed: true,
            ..base_evidence()
        });
        let header = fp.header_value();
        assert!(header.starts_with("classification=agent:claude-code;tty=false;session=s1"));
        assert!(header.contains(";override=allow-unattributed;"));
        assert!(header.contains("markers="));
        assert!(header.contains("ancestor:claude"));
    }

    #[test]
    fn header_stays_under_daemon_metadata_cap_with_many_markers() {
        // hemd caps metadata values at 256 chars; a marker flood (e.g. all
        // the CLAUDE_* vars) must not push tty/session out of the header.
        let env_names: Vec<String> = (0..30)
            .map(|i| format!("CLAUDE_CODE_SOME_LONGISH_VARIABLE_{i}"))
            .collect();
        let fp = classify(Evidence {
            env_names,
            ancestors: vec!["claude".to_string()],
            session: Some("878d7717-d151-4de6-8173-7018e867aa29".to_string()),
            ..base_evidence()
        });
        let header = fp.header_value();
        assert!(
            header.len() <= 256,
            "header too long ({}): {header}",
            header.len()
        );
        assert!(header.contains(";session="));
        // Strong evidence only in the header; the flood stays in `markers`.
        assert!(header.contains("markers=ancestor:claude"));
        assert!(fp.markers.len() > 20);
    }

    #[test]
    fn labels_are_sanitized_for_delimiters() {
        let fp = classify(Evidence {
            hem_caller: Some("weird;label=x,y z".to_string()),
            ..base_evidence()
        });
        // ';', '=', ',' and non-graphic chars are stripped from the label.
        assert_eq!(fp.classification, "agent:weirdlabelxyz");
    }
}
