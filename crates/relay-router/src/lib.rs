//! Deterministic routing primitives.

use relay_wire::{Envelope, MessageId, Priority};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingPolicy {
    DirectOnly,
    ControlledFlood,
    BinarySprayAndWait,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerSnapshot {
    pub peer_token: u64,
    pub is_destination: bool,
    pub already_has_message: bool,
    pub accepts_courier_data: bool,
    pub encounter_score: u16,
    pub queue_pressure: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardReason {
    DirectDestination,
    ControlledFlood,
    BetterCourier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForwardPlan {
    pub message_id: MessageId,
    pub peer_token: u64,
    pub transferred_copies: u16,
    pub retained_copies: u16,
    pub reason: ForwardReason,
}

impl ForwardPlan {
    #[must_use]
    pub fn conserves(&self, previous_budget: u16) -> bool {
        self.transferred_copies
            .checked_add(self.retained_copies)
            .is_some_and(|total| total == previous_budget)
    }
}

#[must_use]
pub fn plan_forward(
    envelope: &Envelope,
    peer: PeerSnapshot,
    policy: RoutingPolicy,
) -> Option<ForwardPlan> {
    if envelope.is_expired()
        || envelope.hops_taken >= envelope.hop_limit
        || peer.already_has_message
    {
        return None;
    }

    if peer.is_destination {
        return Some(ForwardPlan {
            message_id: envelope.id,
            peer_token: peer.peer_token,
            transferred_copies: 1,
            retained_copies: envelope.copy_budget.saturating_sub(1),
            reason: ForwardReason::DirectDestination,
        });
    }

    if !peer.accepts_courier_data || matches!(policy, RoutingPolicy::DirectOnly) {
        return None;
    }

    match policy {
        RoutingPolicy::DirectOnly => None,
        RoutingPolicy::ControlledFlood => {
            if envelope.copy_budget == 0 {
                return None;
            }
            Some(ForwardPlan {
                message_id: envelope.id,
                peer_token: peer.peer_token,
                transferred_copies: 1,
                retained_copies: envelope.copy_budget - 1,
                reason: ForwardReason::ControlledFlood,
            })
        }
        RoutingPolicy::BinarySprayAndWait => {
            let (retained_copies, transferred_copies) = binary_spray_split(envelope.copy_budget)?;
            Some(ForwardPlan {
                message_id: envelope.id,
                peer_token: peer.peer_token,
                transferred_copies,
                retained_copies,
                reason: ForwardReason::BetterCourier,
            })
        }
    }
}

#[must_use]
pub const fn binary_spray_split(copy_budget: u16) -> Option<(u16, u16)> {
    if copy_budget <= 1 {
        return None;
    }
    let transferred = copy_budget / 2;
    let retained = copy_budget - transferred;
    Some((retained, transferred))
}

#[must_use]
pub fn queue_value(envelope: &Envelope, destination_likelihood: u16) -> u64 {
    let priority_weight = match envelope.priority {
        Priority::Control => 6,
        Priority::Safety => 5,
        Priority::DirectText => 4,
        Priority::RoomHistory => 3,
        Priority::Manifest => 2,
        Priority::Bulk => 1,
    };
    let remaining_fraction = envelope
        .lifetime_ms
        .saturating_sub(envelope.age_ms)
        .saturating_mul(1_000)
        / envelope.lifetime_ms.max(1);
    priority_weight * 1_000_000 + u64::from(destination_likelihood) * 1_000 + remaining_fraction
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_wire::{MessageId, Priority};

    fn envelope(copy_budget: u16) -> Envelope {
        Envelope {
            id: MessageId([1; 16]),
            destination_hint: [2; 16],
            lifetime_ms: 10_000,
            age_ms: 0,
            hop_limit: 8,
            hops_taken: 0,
            copy_budget,
            priority: Priority::DirectText,
            ciphertext: vec![42],
        }
    }

    fn courier() -> PeerSnapshot {
        PeerSnapshot {
            peer_token: 44,
            is_destination: false,
            already_has_message: false,
            accepts_courier_data: true,
            encounter_score: 500,
            queue_pressure: 0,
        }
    }

    #[test]
    fn binary_spray_conserves_every_valid_budget() {
        for budget in 2..=relay_wire::MAX_COPY_BUDGET {
            let plan = plan_forward(
                &envelope(budget),
                courier(),
                RoutingPolicy::BinarySprayAndWait,
            )
            .expect("budget above one can be split");
            assert!(plan.conserves(budget));
            assert!(plan.transferred_copies > 0);
            assert!(plan.retained_copies > 0);
        }
    }

    #[test]
    fn one_copy_waits_for_destination() {
        assert_eq!(
            plan_forward(&envelope(1), courier(), RoutingPolicy::BinarySprayAndWait),
            None
        );
    }

    #[test]
    fn direct_delivery_uses_one_copy() {
        let mut peer = courier();
        peer.is_destination = true;
        let plan = plan_forward(&envelope(4), peer, RoutingPolicy::DirectOnly)
            .expect("destination always wins");
        assert_eq!(plan.transferred_copies, 1);
        assert!(plan.conserves(4));
    }
}
