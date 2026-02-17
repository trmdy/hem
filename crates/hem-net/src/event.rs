use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub subject: String,
    pub payload: Vec<u8>,
    pub timestamp: DateTime<Utc>,
}

impl Event {
    pub fn new(subject: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            subject: subject.into(),
            payload: payload.into(),
            timestamp: Utc::now(),
        }
    }

    pub(crate) fn from_nats_message(message: async_nats::Message) -> Self {
        Self {
            subject: message.subject.to_string(),
            payload: message.payload.to_vec(),
            timestamp: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_builder_sets_fields() {
        let event = Event::new("smi.agent.started", b"ok".to_vec());
        assert_eq!(event.subject, "smi.agent.started");
        assert_eq!(event.payload, b"ok".to_vec());
    }
}
