pub mod ids {
    pub const CANONICAL_ULID_LENGTH: usize = 26;
    const ULID_TIMESTAMP_LENGTH: usize = 10;

    pub fn generate_entropy_prefixed_ulid() -> String {
        reorder_ulid_for_entropy_prefix(ulid::Ulid::new().to_string().to_lowercase().as_str())
    }

    pub fn generate_prefixed_entropy_id(prefix: &str) -> String {
        let trimmed = prefix.trim();
        if trimmed.is_empty() {
            return generate_entropy_prefixed_ulid();
        }
        format!("{trimmed}_{}", generate_entropy_prefixed_ulid())
    }

    pub fn reorder_ulid_for_entropy_prefix(canonical: &str) -> String {
        if canonical.len() != CANONICAL_ULID_LENGTH {
            return canonical.to_string();
        }

        let (timestamp, entropy) = canonical.split_at(ULID_TIMESTAMP_LENGTH);
        format!("{entropy}{timestamp}")
    }
}

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

    #[test]
    fn ulid_reordering_places_entropy_first() {
        let canonical = "01arz3ndektsv4rrffq69g5fav";
        let reordered = ids::reorder_ulid_for_entropy_prefix(canonical);
        assert_eq!(reordered, "tsv4rrffq69g5fav01arz3ndek");
    }

    #[test]
    fn generated_entropy_prefixed_ulid_has_expected_shape() {
        let value = ids::generate_entropy_prefixed_ulid();
        assert_eq!(value.len(), ids::CANONICAL_ULID_LENGTH);
        assert!(value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit()));
    }

    #[test]
    fn generated_prefixed_entropy_id_has_expected_shape() {
        let value = ids::generate_prefixed_entropy_id("wf");
        assert!(value.starts_with("wf_"));
        let suffix = value
            .split_once('_')
            .map(|(_, tail)| tail)
            .expect("prefix separator");
        assert_eq!(suffix.len(), ids::CANONICAL_ULID_LENGTH);
        assert!(suffix
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit()));
    }
}
