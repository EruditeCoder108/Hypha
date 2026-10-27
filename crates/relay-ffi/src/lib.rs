//! Deliberately narrow boundary for generated bindings.
//!
//! Phase 0 exposes safe metadata only. The first native spike will choose and
//! generate the ABI rather than grow hand-written pointer management.

#[must_use]
pub const fn protocol_version() -> u8 {
    relay_wire::WIRE_VERSION
}

#[must_use]
pub const fn outer_header_len() -> usize {
    relay_wire::HEADER_LEN
}

#[must_use]
pub fn new_default_node() -> relay_core::Node {
    relay_core::Node::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_core_protocol_metadata() {
        assert_eq!(protocol_version(), 1);
        assert_eq!(outer_header_len(), 64);
        assert_eq!(new_default_node().envelope_count(), 0);
    }
}
