fn main() {
    use relay_router::RoutingPolicy;
    use relay_sim::{CampusScenarioConfig, run_campus_scenario};

    let baseline = CampusScenarioConfig::default();
    for (label, policy, copies, last_copy_destination_probe) in [
        ("direct", RoutingPolicy::DirectOnly, 1, true),
        (
            "spray-4-private-probe",
            RoutingPolicy::BinarySprayAndWait,
            4,
            true,
        ),
        (
            "spray-8-without-private-probe",
            RoutingPolicy::BinarySprayAndWait,
            8,
            false,
        ),
        (
            "spray-8-private-probe",
            RoutingPolicy::BinarySprayAndWait,
            8,
            true,
        ),
        (
            "spray-12-private-probe",
            RoutingPolicy::BinarySprayAndWait,
            12,
            true,
        ),
        (
            "spray-16-private-probe",
            RoutingPolicy::BinarySprayAndWait,
            16,
            true,
        ),
        (
            "spray-24-private-probe",
            RoutingPolicy::BinarySprayAndWait,
            24,
            true,
        ),
        (
            "spray-32-private-probe",
            RoutingPolicy::BinarySprayAndWait,
            32,
            true,
        ),
    ] {
        let report = run_campus_scenario(CampusScenarioConfig {
            routing_policy: policy,
            copy_budget: copies,
            last_copy_destination_probe,
            ..baseline
        });
        println!(
            "{label}: delivered={}/{} ({}.{:01}%), mean_encounters={}, p95_encounters={}, \
             transmissions={}, tx_per_delivery={}.{:03}",
            report.delivered,
            report.trials,
            report.delivery_ratio_permille / 10,
            report.delivery_ratio_permille % 10,
            report.mean_delivery_encounters,
            report.p95_delivery_encounters,
            report.transmissions,
            report.transmissions_per_delivery_milli / 1_000,
            report.transmissions_per_delivery_milli % 1_000,
        );
    }
}
