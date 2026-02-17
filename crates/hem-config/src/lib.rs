#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceDescriptor {
    pub service: &'static str,
    pub daemon: &'static str,
    pub sprint: u8,
}

pub const SPRINT_1_SERVICES: [ServiceDescriptor; 4] = [
    ServiceDescriptor {
        service: "smi",
        daemon: "smid",
        sprint: 1,
    },
    ServiceDescriptor {
        service: "vis",
        daemon: "visd",
        sprint: 1,
    },
    ServiceDescriptor {
        service: "bod",
        daemon: "bodd",
        sprint: 1,
    },
    ServiceDescriptor {
        service: "skip",
        daemon: "skipd",
        sprint: 1,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sprint_one_has_expected_services() {
        assert_eq!(SPRINT_1_SERVICES.len(), 4);
        assert_eq!(SPRINT_1_SERVICES[0].service, "smi");
        assert_eq!(SPRINT_1_SERVICES[3].daemon, "skipd");
    }
}
