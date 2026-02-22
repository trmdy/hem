pub mod topics {
    pub const SMI_AGENT_RUN_REQUESTED: &str = "smi.agent.run_requested";
    pub const VIS_MEMORY_SYNC_REQUESTED: &str = "vis.memory.sync_requested";
    pub const BOD_ROOT_MOUNTED: &str = "bod.root.mounted";
    pub const SKIP_CONTAINER_SPAWN_REQUESTED: &str = "skip.container.spawn_requested";

    pub const SKIP_CREATED: &str = "skip.created";
    pub const SKIP_STOPPED: &str = "skip.stopped";
    pub const SKIP_DESTROYED: &str = "skip.destroyed";

    pub const BOD_FILE_WRITTEN: &str = "bod.file.written";
    pub const BOD_FILE_DELETED: &str = "bod.file.deleted";
    pub const BOD_ROOT_CREATED: &str = "bod.root.created";
    pub const BOD_ROOT_DELETED: &str = "bod.root.deleted";

    pub const VIS_IDENTITY_CREATED: &str = "vis.identity.created";
    pub const VIS_MEMORY_STORED: &str = "vis.memory.stored";
    pub const VIS_CONTEXT_INJECTED: &str = "vis.context.injected";

    pub const SMI_AGENT_STARTED: &str = "smi.agent.started";
    pub const SMI_AGENT_COMPLETED: &str = "smi.agent.completed";
    pub const SMI_AGENT_ERRORED: &str = "smi.agent.errored";
    pub const SMI_AGENT_STOPPED: &str = "smi.agent.stopped";
    pub const SMI_LOOP_ITERATION: &str = "smi.loop.iteration";
    pub const SMI_LOOP_STOP_CONDITION_EVALUATED: &str = "smi.loop.stop_condition_evaluated";

    pub const HEM_SECRET_READ: &str = "hem.secret.read";
    pub const HEM_SECRET_WRITTEN: &str = "hem.secret.written";
    pub const HEM_SECRET_DELETED: &str = "hem.secret.deleted";
    pub const HEM_TOKEN_ISSUED: &str = "hem.token.issued";
    pub const HEM_TOKEN_REVOKED: &str = "hem.token.revoked";
    pub const HEM_APPROVAL_REQUESTED: &str = "hem.approval.requested";
    pub const HEM_APPROVAL_RESOLVED: &str = "hem.approval.resolved";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemEvent {
    AgentRunRequested,
    MemorySyncRequested,
    FileRootMounted,
    ContainerSpawnRequested,
}

impl SystemEvent {
    pub fn topic(&self) -> &'static str {
        match self {
            Self::AgentRunRequested => topics::SMI_AGENT_RUN_REQUESTED,
            Self::MemorySyncRequested => topics::VIS_MEMORY_SYNC_REQUESTED,
            Self::FileRootMounted => topics::BOD_ROOT_MOUNTED,
            Self::ContainerSpawnRequested => topics::SKIP_CONTAINER_SPAWN_REQUESTED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_topics_are_stable() {
        assert_eq!(
            SystemEvent::AgentRunRequested.topic(),
            topics::SMI_AGENT_RUN_REQUESTED
        );
        assert_eq!(
            SystemEvent::ContainerSpawnRequested.topic(),
            topics::SKIP_CONTAINER_SPAWN_REQUESTED
        );
    }

    #[test]
    fn sprint_one_daemon_event_topics_are_stable() {
        assert_eq!(topics::SKIP_CREATED, "skip.created");
        assert_eq!(topics::BOD_ROOT_CREATED, "bod.root.created");
        assert_eq!(topics::VIS_CONTEXT_INJECTED, "vis.context.injected");
        assert_eq!(topics::SMI_AGENT_STARTED, "smi.agent.started");
        assert_eq!(
            topics::SMI_LOOP_STOP_CONDITION_EVALUATED,
            "smi.loop.stop_condition_evaluated"
        );
        assert_eq!(topics::HEM_SECRET_WRITTEN, "hem.secret.written");
        assert_eq!(topics::HEM_APPROVAL_REQUESTED, "hem.approval.requested");
    }
}
