//! Small deterministic scenarios built on the same state machine as the app.

use relay_core::{CoreCommand, CoreEvent, Node, NodeConfig};
use relay_router::{ForwardPlan, PeerSnapshot, RoutingPolicy};
use relay_wire::{Envelope, MessageId, Priority};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScenarioReport {
    pub node_count: usize,
    pub transmissions: usize,
    pub delivered: usize,
    pub elapsed_ms: u64,
}

/// A repeatable campus-like mobility workload. Nodes meet mostly inside their
/// class/community, with rarer cross-community encounters acting as bridges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CampusScenarioConfig {
    pub node_count: usize,
    pub community_count: usize,
    pub trials: usize,
    pub max_encounters: usize,
    pub encounter_ms: u64,
    pub within_community_permille: u16,
    pub copy_budget: u16,
    pub routing_policy: RoutingPolicy,
    pub last_copy_destination_probe: bool,
    pub seed: u64,
}

impl Default for CampusScenarioConfig {
    fn default() -> Self {
        Self {
            node_count: 300,
            community_count: 12,
            trials: 250,
            max_encounters: 30_000,
            encounter_ms: 500,
            within_community_permille: 850,
            copy_budget: 8,
            routing_policy: RoutingPolicy::BinarySprayAndWait,
            last_copy_destination_probe: true,
            seed: 0x5245_4c41_5943_414d,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CampusReport {
    pub node_count: usize,
    pub trials: usize,
    pub delivered: usize,
    pub delivery_ratio_permille: u16,
    pub mean_delivery_encounters: usize,
    pub p95_delivery_encounters: usize,
    pub transmissions: usize,
    pub transmissions_per_delivery_milli: usize,
}

/// Runs many deterministic source-to-destination trials under clustered
/// mobility. Source and destination always start in different communities.
///
/// # Panics
///
/// Panics when the configuration cannot form a useful campus scenario.
#[must_use]
pub fn run_campus_scenario(config: CampusScenarioConfig) -> CampusReport {
    assert!(
        config.node_count >= 4,
        "a campus scenario needs at least four nodes"
    );
    assert!(
        (2..=config.node_count).contains(&config.community_count),
        "campus communities must fit inside the node population"
    );
    assert!(
        config.trials > 0,
        "a campus scenario needs at least one trial"
    );
    assert!(
        config.max_encounters > 0,
        "a campus scenario needs encounters"
    );
    assert!(
        config.encounter_ms > 0,
        "encounter duration must be positive"
    );
    assert!(
        config.within_community_permille <= 1_000,
        "within-community probability is out of range"
    );
    assert!(config.copy_budget > 0, "copy budget must be positive");

    let mut random = DeterministicRandom::new(config.seed);
    let mut delivery_latencies = Vec::with_capacity(config.trials);
    let mut transmissions = 0_usize;

    for trial in 0..config.trials {
        let source = random.bounded(config.node_count);
        let destination = choose_other_community_node(
            &mut random,
            source,
            config.node_count,
            config.community_count,
        );
        let node_config = NodeConfig {
            max_envelopes: 64,
            max_storage_bytes: 1024 * 1024,
            routing_policy: config.routing_policy,
        };
        let mut nodes: Vec<Node> = (0..config.node_count)
            .map(|_| Node::new(node_config))
            .collect();
        let mut id = [0_u8; 16];
        id[..8].copy_from_slice(&u64::try_from(trial).unwrap_or(u64::MAX).to_be_bytes());
        id[8..].copy_from_slice(&random.next_u64().to_be_bytes());
        let message = Envelope {
            id: MessageId(id),
            destination_hint: [2; 16],
            lifetime_ms: u64::try_from(config.max_encounters)
                .unwrap_or(u64::MAX)
                .saturating_mul(config.encounter_ms)
                .saturating_add(1),
            age_ms: 0,
            hop_limit: 32,
            hops_taken: 0,
            copy_budget: config.copy_budget,
            priority: Priority::DirectText,
            ciphertext: b"campus-mesh-simulation".to_vec(),
        };
        nodes[source].apply(CoreCommand::AcceptLocal(message.clone()));

        for encounter in 1..=config.max_encounters {
            let (first, second) = choose_encounter(&mut random, config);
            if attempt_transfer(
                &mut nodes,
                first,
                second,
                destination,
                message.id,
                config.last_copy_destination_probe,
                &mut transmissions,
            ) || attempt_transfer(
                &mut nodes,
                second,
                first,
                destination,
                message.id,
                config.last_copy_destination_probe,
                &mut transmissions,
            ) {
                delivery_latencies.push(encounter);
                break;
            }
        }
    }

    delivery_latencies.sort_unstable();
    let delivered = delivery_latencies.len();
    let total_latency = delivery_latencies.iter().sum::<usize>();
    let p95_index = delivered.saturating_mul(95).div_ceil(100).saturating_sub(1);
    CampusReport {
        node_count: config.node_count,
        trials: config.trials,
        delivered,
        delivery_ratio_permille: u16::try_from(delivered.saturating_mul(1_000) / config.trials)
            .unwrap_or(1_000),
        mean_delivery_encounters: if delivered == 0 {
            0
        } else {
            total_latency / delivered
        },
        p95_delivery_encounters: delivery_latencies.get(p95_index).copied().unwrap_or(0),
        transmissions,
        transmissions_per_delivery_milli: if delivered == 0 {
            0
        } else {
            transmissions.saturating_mul(1_000) / delivered
        },
    }
}

/// Runs a deterministic message along a connected linear topology.
///
/// # Panics
///
/// Panics when fewer than two nodes are requested.
#[must_use]
pub fn run_linear_chain(node_count: usize) -> ScenarioReport {
    assert!(node_count >= 2, "a chain needs at least two nodes");
    let mut nodes: Vec<Node> = (0..node_count).map(|_| Node::default()).collect();
    let message = Envelope {
        id: MessageId([1; 16]),
        destination_hint: [2; 16],
        lifetime_ms: 60_000,
        age_ms: 0,
        hop_limit: u8::try_from(node_count).unwrap_or(u8::MAX),
        hops_taken: 0,
        copy_budget: 16,
        priority: Priority::DirectText,
        ciphertext: b"phase-zero-simulation".to_vec(),
    };
    nodes[0].apply(CoreCommand::AcceptLocal(message));

    let mut report = ScenarioReport {
        node_count,
        ..ScenarioReport::default()
    };

    for index in 0..node_count - 1 {
        let is_destination = index + 1 == node_count - 1;
        let peer = PeerSnapshot {
            peer_token: u64::try_from(index + 1).unwrap_or(u64::MAX),
            is_destination,
            already_has_message: false,
            accepts_courier_data: true,
            encounter_score: 500,
            queue_pressure: 0,
        };
        let plans = nodes[index].apply(CoreCommand::PeerEncounter(peer));
        let plan = plans.into_iter().find_map(|event| match event {
            CoreEvent::ForwardPlanned(plan) => Some(plan),
            _ => None,
        });
        let Some(plan) = plan else {
            break;
        };
        if transfer(&mut nodes, index, index + 1, plan) {
            report.transmissions += 1;
            report.elapsed_ms += 250;
            if is_destination {
                report.delivered += 1;
            }
        }
    }
    report
}

fn transfer(nodes: &mut [Node], from: usize, to: usize, plan: ForwardPlan) -> bool {
    let Some(mut outbound) = nodes[from].envelope(plan.message_id).cloned() else {
        return false;
    };
    outbound.copy_budget = plan.transferred_copies;
    outbound.hops_taken = outbound.hops_taken.saturating_add(1);

    let commit = nodes[from].apply(CoreCommand::CommitForward(plan));
    if !matches!(commit.as_slice(), [CoreEvent::ForwardCommitted(_)]) {
        return false;
    }
    matches!(
        nodes[to].apply(CoreCommand::Receive(outbound)).as_slice(),
        [CoreEvent::EnvelopeStored(_)]
    )
}

fn attempt_transfer(
    nodes: &mut [Node],
    from: usize,
    to: usize,
    destination: usize,
    message_id: MessageId,
    last_copy_destination_probe: bool,
    transmissions: &mut usize,
) -> bool {
    let Some(envelope) = nodes[from].envelope(message_id) else {
        return false;
    };
    if nodes[to].envelope(message_id).is_some() {
        return false;
    }
    let peer = PeerSnapshot {
        peer_token: u64::try_from(to).unwrap_or(u64::MAX),
        is_destination: to == destination
            && (last_copy_destination_probe || envelope.copy_budget > 1),
        already_has_message: false,
        accepts_courier_data: true,
        encounter_score: 500,
        queue_pressure: 0,
    };
    let plan = nodes[from]
        .apply(CoreCommand::PeerEncounter(peer))
        .into_iter()
        .find_map(|event| match event {
            CoreEvent::ForwardPlanned(plan) if plan.message_id == message_id => Some(plan),
            _ => None,
        });
    let Some(plan) = plan else { return false };
    if !transfer(nodes, from, to, plan) {
        return false;
    }
    *transmissions = transmissions.saturating_add(1);
    to == destination
}

fn choose_encounter(
    random: &mut DeterministicRandom,
    config: CampusScenarioConfig,
) -> (usize, usize) {
    if random.bounded(1_000) < usize::from(config.within_community_permille) {
        let community = random.bounded(config.community_count);
        let members = community_size(config.node_count, config.community_count, community);
        if members >= 2 {
            let first_member = random.bounded(members);
            let mut second_member = random.bounded(members - 1);
            if second_member >= first_member {
                second_member += 1;
            }
            return (
                community + first_member * config.community_count,
                community + second_member * config.community_count,
            );
        }
    }
    let first = random.bounded(config.node_count);
    let second =
        choose_other_community_node(random, first, config.node_count, config.community_count);
    (first, second)
}

fn choose_other_community_node(
    random: &mut DeterministicRandom,
    node: usize,
    node_count: usize,
    community_count: usize,
) -> usize {
    loop {
        let candidate = random.bounded(node_count);
        if candidate != node && candidate % community_count != node % community_count {
            return candidate;
        }
    }
}

fn community_size(node_count: usize, community_count: usize, community: usize) -> usize {
    if community >= node_count {
        return 0;
    }
    (node_count - 1 - community) / community_count + 1
}

#[derive(Clone, Copy, Debug)]
struct DeterministicRandom(u64);

impl DeterministicRandom {
    const fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.0 = value;
        value.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn bounded(&mut self, upper: usize) -> usize {
        assert!(upper > 0, "random upper bound must be positive");
        usize::try_from(self.next_u64() % u64::try_from(upper).unwrap_or(u64::MAX)).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_node_delivery_is_deterministic() {
        let first = run_linear_chain(2);
        let second = run_linear_chain(2);
        assert_eq!(first, second);
        assert_eq!(first.delivered, 1);
        assert_eq!(first.transmissions, 1);
    }

    #[test]
    fn five_node_chain_delivers_in_four_transmissions() {
        let report = run_linear_chain(5);
        assert_eq!(report.delivered, 1);
        assert_eq!(report.transmissions, 4);
        assert_eq!(report.elapsed_ms, 1_000);
    }

    #[test]
    fn campus_simulation_is_repeatable() {
        let config = CampusScenarioConfig {
            node_count: 80,
            community_count: 8,
            trials: 40,
            max_encounters: 8_000,
            ..CampusScenarioConfig::default()
        };
        assert_eq!(run_campus_scenario(config), run_campus_scenario(config));
    }

    #[test]
    fn bounded_spray_beats_direct_delivery_across_campus_communities() {
        let base = CampusScenarioConfig {
            node_count: 120,
            community_count: 8,
            trials: 120,
            max_encounters: 4_000,
            within_community_permille: 850,
            seed: 7,
            ..CampusScenarioConfig::default()
        };
        let direct = run_campus_scenario(CampusScenarioConfig {
            routing_policy: RoutingPolicy::DirectOnly,
            copy_budget: 1,
            ..base
        });
        let spray = run_campus_scenario(CampusScenarioConfig {
            routing_policy: RoutingPolicy::BinarySprayAndWait,
            copy_budget: 8,
            ..base
        });
        assert!(spray.delivered > direct.delivered);
        assert!(spray.mean_delivery_encounters < direct.mean_delivery_encounters);
        assert!(spray.transmissions <= base.trials * usize::from(base.copy_budget));
    }
}
