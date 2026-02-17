use valhall_events::SystemEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryKind {
    RequestResponse,
    Publish,
}

pub fn delivery_for(event: &SystemEvent) -> DeliveryKind {
    match event {
        SystemEvent::AgentRunRequested | SystemEvent::ContainerSpawnRequested => {
            DeliveryKind::RequestResponse
        }
        SystemEvent::MemorySyncRequested | SystemEvent::FileRootMounted => DeliveryKind::Publish,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_kind_matches_event_shape() {
        assert_eq!(
            delivery_for(&SystemEvent::AgentRunRequested),
            DeliveryKind::RequestResponse
        );
        assert_eq!(
            delivery_for(&SystemEvent::FileRootMounted),
            DeliveryKind::Publish
        );
    }
}
