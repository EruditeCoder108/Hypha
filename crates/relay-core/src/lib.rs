//! Deterministic, transport-neutral Relay node state.

pub mod attachment;

use std::collections::BTreeMap;

use relay_router::{ForwardPlan, PeerSnapshot, RoutingPolicy, plan_forward};
use relay_wire::{Envelope, MessageId, ValidationError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeConfig {
    pub max_envelopes: usize,
    pub max_storage_bytes: usize,
    pub routing_policy: RoutingPolicy,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            max_envelopes: 10_000,
            max_storage_bytes: 64 * 1024 * 1024,
            routing_policy: RoutingPolicy::BinarySprayAndWait,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreCommand {
    AcceptLocal(Envelope),
    Receive(Envelope),
    AdvanceTime { elapsed_ms: u64 },
    PeerEncounter(PeerSnapshot),
    CommitForward(ForwardPlan),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreEvent {
    EnvelopeStored(MessageId),
    DuplicateIgnored(MessageId),
    EnvelopeExpired(MessageId),
    EnvelopeRejected { id: MessageId, reason: RejectReason },
    ForwardPlanned(ForwardPlan),
    ForwardCommitted(MessageId),
    ForwardCommitRejected(MessageId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RejectReason {
    Invalid(ValidationError),
    StoragePressure,
}

#[derive(Debug)]
pub struct Node {
    config: NodeConfig,
    elapsed_ms: u64,
    storage_bytes: usize,
    envelopes: BTreeMap<MessageId, Envelope>,
}

impl Node {
    #[must_use]
    pub const fn new(config: NodeConfig) -> Self {
        Self {
            config,
            elapsed_ms: 0,
            storage_bytes: 0,
            envelopes: BTreeMap::new(),
        }
    }

    pub fn apply(&mut self, command: CoreCommand) -> Vec<CoreEvent> {
        match command {
            CoreCommand::AcceptLocal(envelope) | CoreCommand::Receive(envelope) => {
                vec![self.store(envelope)]
            }
            CoreCommand::AdvanceTime { elapsed_ms } => self.advance_time(elapsed_ms),
            CoreCommand::PeerEncounter(peer) => self.plan_for_peer(peer),
            CoreCommand::CommitForward(plan) => vec![self.commit_forward(plan)],
        }
    }

    #[must_use]
    pub const fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms
    }

    #[must_use]
    pub fn envelope_count(&self) -> usize {
        self.envelopes.len()
    }

    #[must_use]
    pub const fn storage_bytes(&self) -> usize {
        self.storage_bytes
    }

    #[must_use]
    pub fn envelope(&self, id: MessageId) -> Option<&Envelope> {
        self.envelopes.get(&id)
    }

    fn store(&mut self, envelope: Envelope) -> CoreEvent {
        let id = envelope.id;
        if let Err(error) = envelope.validate() {
            return CoreEvent::EnvelopeRejected {
                id,
                reason: RejectReason::Invalid(error),
            };
        }
        if self.envelopes.contains_key(&id) {
            return CoreEvent::DuplicateIgnored(id);
        }
        let encoded_len = envelope.encoded_len();
        let exceeds_count = self.envelopes.len() >= self.config.max_envelopes;
        let exceeds_bytes = self
            .storage_bytes
            .checked_add(encoded_len)
            .is_none_or(|size| size > self.config.max_storage_bytes);
        if exceeds_count || exceeds_bytes {
            return CoreEvent::EnvelopeRejected {
                id,
                reason: RejectReason::StoragePressure,
            };
        }
        self.storage_bytes += encoded_len;
        self.envelopes.insert(id, envelope);
        CoreEvent::EnvelopeStored(id)
    }

    fn advance_time(&mut self, elapsed_ms: u64) -> Vec<CoreEvent> {
        self.elapsed_ms = self.elapsed_ms.saturating_add(elapsed_ms);
        let mut expired = Vec::new();
        for (id, envelope) in &mut self.envelopes {
            envelope.age_ms = envelope.age_ms.saturating_add(elapsed_ms);
            if envelope.is_expired() {
                expired.push(*id);
            }
        }
        let mut events = Vec::with_capacity(expired.len());
        for id in expired {
            if let Some(removed) = self.envelopes.remove(&id) {
                self.storage_bytes = self.storage_bytes.saturating_sub(removed.encoded_len());
                events.push(CoreEvent::EnvelopeExpired(id));
            }
        }
        events
    }

    fn plan_for_peer(&self, peer: PeerSnapshot) -> Vec<CoreEvent> {
        let mut envelopes: Vec<_> = self.envelopes.values().collect();
        envelopes.sort_by_key(|envelope| (envelope.priority, envelope.id));
        envelopes
            .into_iter()
            .filter_map(|envelope| {
                plan_forward(envelope, peer, self.config.routing_policy)
                    .map(CoreEvent::ForwardPlanned)
            })
            .collect()
    }

    fn commit_forward(&mut self, plan: ForwardPlan) -> CoreEvent {
        let Some(envelope) = self.envelopes.get(&plan.message_id) else {
            return CoreEvent::ForwardCommitRejected(plan.message_id);
        };
        if plan.transferred_copies == 0 || !plan.conserves(envelope.copy_budget) {
            return CoreEvent::ForwardCommitRejected(plan.message_id);
        }

        if plan.retained_copies == 0 {
            if let Some(removed) = self.envelopes.remove(&plan.message_id) {
                self.storage_bytes = self.storage_bytes.saturating_sub(removed.encoded_len());
            }
        } else if let Some(envelope) = self.envelopes.get_mut(&plan.message_id) {
            envelope.copy_budget = plan.retained_copies;
        }
        CoreEvent::ForwardCommitted(plan.message_id)
    }
}

impl Default for Node {
    fn default() -> Self {
        Self::new(NodeConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_wire::Priority;

    fn envelope(id_byte: u8, lifetime_ms: u64) -> Envelope {
        Envelope {
            id: MessageId([id_byte; 16]),
            destination_hint: [8; 16],
            lifetime_ms,
            age_ms: 0,
            hop_limit: 8,
            hops_taken: 0,
            copy_budget: 4,
            priority: Priority::DirectText,
            ciphertext: vec![1, 2, 3],
        }
    }

    #[test]
    fn duplicate_never_increases_storage() {
        let mut node = Node::default();
        let message = envelope(1, 1_000);
        assert_eq!(
            node.apply(CoreCommand::Receive(message.clone())),
            vec![CoreEvent::EnvelopeStored(message.id)]
        );
        let bytes = node.storage_bytes();
        assert_eq!(
            node.apply(CoreCommand::Receive(message.clone())),
            vec![CoreEvent::DuplicateIgnored(message.id)]
        );
        assert_eq!(node.storage_bytes(), bytes);
        assert_eq!(node.envelope_count(), 1);
    }

    #[test]
    fn monotonic_elapsed_time_expires_without_wall_clock() {
        let mut node = Node::default();
        let message = envelope(2, 1_000);
        node.apply(CoreCommand::AcceptLocal(message.clone()));
        assert!(
            node.apply(CoreCommand::AdvanceTime { elapsed_ms: 999 })
                .is_empty()
        );
        assert_eq!(node.envelope(message.id).map(|item| item.age_ms), Some(999));
        assert_eq!(
            node.apply(CoreCommand::AdvanceTime { elapsed_ms: 1 }),
            vec![CoreEvent::EnvelopeExpired(message.id)]
        );
        assert_eq!(node.envelope_count(), 0);
    }

    #[test]
    fn storage_limit_rejects_before_allocation_growth() {
        let config = NodeConfig {
            max_envelopes: 1,
            max_storage_bytes: 1_000,
            routing_policy: RoutingPolicy::BinarySprayAndWait,
        };
        let mut node = Node::new(config);
        node.apply(CoreCommand::Receive(envelope(1, 1_000)));
        assert!(matches!(
            node.apply(CoreCommand::Receive(envelope(2, 1_000)))
                .as_slice(),
            [CoreEvent::EnvelopeRejected {
                reason: RejectReason::StoragePressure,
                ..
            }]
        ));
    }

    #[test]
    fn stale_or_forged_forward_plan_cannot_create_copies() {
        let mut node = Node::default();
        let message = envelope(3, 1_000);
        node.apply(CoreCommand::Receive(message.clone()));
        let forged = ForwardPlan {
            message_id: message.id,
            peer_token: 7,
            transferred_copies: 4,
            retained_copies: 4,
            reason: relay_router::ForwardReason::BetterCourier,
        };
        assert_eq!(
            node.apply(CoreCommand::CommitForward(forged)),
            vec![CoreEvent::ForwardCommitRejected(message.id)]
        );
        assert_eq!(
            node.envelope(message.id).map(|item| item.copy_budget),
            Some(4)
        );
    }
}
