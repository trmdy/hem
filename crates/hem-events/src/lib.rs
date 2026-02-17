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
            Self::AgentRunRequested => "smi.agent.run_requested",
            Self::MemorySyncRequested => "vis.memory.sync_requested",
            Self::FileRootMounted => "bod.root.mounted",
            Self::ContainerSpawnRequested => "skip.container.spawn_requested",
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
            "smi.agent.run_requested"
        );
        assert_eq!(
            SystemEvent::ContainerSpawnRequested.topic(),
            "skip.container.spawn_requested"
        );
    }
}
