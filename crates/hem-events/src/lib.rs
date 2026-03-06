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
    pub const SMI_HARNESS_HEALTHY: &str = "smi.harness.healthy";
    pub const SMI_HARNESS_UNHEALTHY: &str = "smi.harness.unhealthy";
    pub const SMI_LOOP_ITERATION: &str = "smi.loop.iteration";
    pub const SMI_LOOP_STOP_CONDITION_EVALUATED: &str = "smi.loop.stop_condition_evaluated";

    pub const HEM_SECRET_READ: &str = "hem.secret.read";
    pub const HEM_SECRET_WRITTEN: &str = "hem.secret.written";
    pub const HEM_SECRET_DELETED: &str = "hem.secret.deleted";
    pub const HEM_TOKEN_ISSUED: &str = "hem.token.issued";
    pub const HEM_TOKEN_REVOKED: &str = "hem.token.revoked";
    pub const HEM_APPROVAL_REQUESTED: &str = "hem.approval.requested";
    pub const HEM_APPROVAL_RESOLVED: &str = "hem.approval.resolved";

    pub const SLIK_TASK_CREATED: &str = "slik.task.created";
    pub const SLIK_TASK_CLAIMED: &str = "slik.task.claimed";
    pub const SLIK_TASK_RELEASED: &str = "slik.task.released";
    pub const SLIK_TASK_UPDATED: &str = "slik.task.updated";
    pub const SLIK_TASK_COMPLETED: &str = "slik.task.completed";

    pub const MYSE_SESSION_CREATED: &str = "myse.session.created";
    pub const MYSE_SESSION_READY: &str = "myse.session.ready";
    pub const MYSE_SESSION_PASSED: &str = "myse.session.passed";
    pub const MYSE_SESSION_FAILED: &str = "myse.session.failed";
    pub const MYSE_SESSION_ERRORED: &str = "myse.session.errored";
    pub const MYSE_SESSION_STOPPED: &str = "myse.session.stopped";
    pub const MYSE_SESSION_EXPIRED: &str = "myse.session.expired";
    pub const MYSE_SESSION_DESTROYED: &str = "myse.session.destroyed";

    pub const TING_CHANNEL_CREATED: &str = "ting.channel.created";
    pub const TING_CHANNEL_PROMOTED: &str = "ting.channel.promoted";
    pub const TING_CHANNEL_JOINED: &str = "ting.channel.joined";
    pub const TING_CHANNEL_LEFT: &str = "ting.channel.left";
    pub const TING_CHANNEL_INVITED: &str = "ting.channel.invited";
    pub const TING_MESSAGE_SENT: &str = "ting.message.sent";
    pub const TING_DM_SENT: &str = "ting.dm.sent";
    pub const TING_CHANNEL_READ_MARKED: &str = "ting.channel.read_marked";
    pub const TING_DM_READ_MARKED: &str = "ting.dm.read_marked";

    pub const HJUL_SCHEDULE_FIRED: &str = "hjul.schedule.fired";
    pub const HJUL_SUBSCRIPTION_TRIGGERED: &str = "hjul.subscription.triggered";
    pub const HJUL_WEBHOOK_RECEIVED: &str = "hjul.webhook.received";
    pub const HJUL_JOB_STARTED: &str = "hjul.job.started";
    pub const HJUL_JOB_COMPLETED: &str = "hjul.job.completed";
    pub const HJUL_JOB_ERRORED: &str = "hjul.job.errored";
    pub const HJUL_JOB_QUEUED: &str = "hjul.job.queued";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemEvent {
    AgentRunRequested,
    MemorySyncRequested,
    FileRootMounted,
    ContainerSpawnRequested,
    MessageSent,
    DirectMessageSent,
    ChannelCreated,
}

impl SystemEvent {
    pub fn topic(&self) -> &'static str {
        match self {
            Self::AgentRunRequested => topics::SMI_AGENT_RUN_REQUESTED,
            Self::MemorySyncRequested => topics::VIS_MEMORY_SYNC_REQUESTED,
            Self::FileRootMounted => topics::BOD_ROOT_MOUNTED,
            Self::ContainerSpawnRequested => topics::SKIP_CONTAINER_SPAWN_REQUESTED,
            Self::MessageSent => topics::TING_MESSAGE_SENT,
            Self::DirectMessageSent => topics::TING_DM_SENT,
            Self::ChannelCreated => topics::TING_CHANNEL_CREATED,
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
        assert_eq!(SystemEvent::MessageSent.topic(), topics::TING_MESSAGE_SENT);
        assert_eq!(SystemEvent::DirectMessageSent.topic(), topics::TING_DM_SENT);
        assert_eq!(
            SystemEvent::ChannelCreated.topic(),
            topics::TING_CHANNEL_CREATED
        );
    }

    #[test]
    fn sprint_one_daemon_event_topics_are_stable() {
        assert_eq!(topics::SKIP_CREATED, "skip.created");
        assert_eq!(topics::BOD_ROOT_CREATED, "bod.root.created");
        assert_eq!(topics::VIS_CONTEXT_INJECTED, "vis.context.injected");
        assert_eq!(topics::SMI_AGENT_STARTED, "smi.agent.started");
        assert_eq!(topics::SMI_HARNESS_HEALTHY, "smi.harness.healthy");
        assert_eq!(topics::SMI_HARNESS_UNHEALTHY, "smi.harness.unhealthy");
        assert_eq!(
            topics::SMI_LOOP_STOP_CONDITION_EVALUATED,
            "smi.loop.stop_condition_evaluated"
        );
        assert_eq!(topics::HEM_SECRET_WRITTEN, "hem.secret.written");
        assert_eq!(topics::HEM_APPROVAL_REQUESTED, "hem.approval.requested");
    }

    #[test]
    fn sprint_two_slik_topics_are_stable() {
        assert_eq!(topics::SLIK_TASK_CREATED, "slik.task.created");
        assert_eq!(topics::SLIK_TASK_CLAIMED, "slik.task.claimed");
        assert_eq!(topics::SLIK_TASK_RELEASED, "slik.task.released");
        assert_eq!(topics::SLIK_TASK_UPDATED, "slik.task.updated");
        assert_eq!(topics::SLIK_TASK_COMPLETED, "slik.task.completed");
    }

    #[test]
    fn ting_topics_are_stable() {
        assert_eq!(topics::TING_CHANNEL_CREATED, "ting.channel.created");
        assert_eq!(topics::TING_CHANNEL_PROMOTED, "ting.channel.promoted");
        assert_eq!(topics::TING_CHANNEL_JOINED, "ting.channel.joined");
        assert_eq!(topics::TING_CHANNEL_LEFT, "ting.channel.left");
        assert_eq!(topics::TING_CHANNEL_INVITED, "ting.channel.invited");
        assert_eq!(topics::TING_MESSAGE_SENT, "ting.message.sent");
        assert_eq!(topics::TING_DM_SENT, "ting.dm.sent");
        assert_eq!(topics::TING_CHANNEL_READ_MARKED, "ting.channel.read_marked");
        assert_eq!(topics::TING_DM_READ_MARKED, "ting.dm.read_marked");
    }

    #[test]
    fn myse_topics_are_stable() {
        assert_eq!(topics::MYSE_SESSION_CREATED, "myse.session.created");
        assert_eq!(topics::MYSE_SESSION_READY, "myse.session.ready");
        assert_eq!(topics::MYSE_SESSION_PASSED, "myse.session.passed");
        assert_eq!(topics::MYSE_SESSION_FAILED, "myse.session.failed");
        assert_eq!(topics::MYSE_SESSION_ERRORED, "myse.session.errored");
        assert_eq!(topics::MYSE_SESSION_STOPPED, "myse.session.stopped");
        assert_eq!(topics::MYSE_SESSION_EXPIRED, "myse.session.expired");
        assert_eq!(topics::MYSE_SESSION_DESTROYED, "myse.session.destroyed");
    }

    #[test]
    fn hjul_topics_are_stable() {
        assert_eq!(topics::HJUL_SCHEDULE_FIRED, "hjul.schedule.fired");
        assert_eq!(
            topics::HJUL_SUBSCRIPTION_TRIGGERED,
            "hjul.subscription.triggered"
        );
        assert_eq!(topics::HJUL_WEBHOOK_RECEIVED, "hjul.webhook.received");
        assert_eq!(topics::HJUL_JOB_STARTED, "hjul.job.started");
        assert_eq!(topics::HJUL_JOB_COMPLETED, "hjul.job.completed");
        assert_eq!(topics::HJUL_JOB_ERRORED, "hjul.job.errored");
        assert_eq!(topics::HJUL_JOB_QUEUED, "hjul.job.queued");
    }
}
