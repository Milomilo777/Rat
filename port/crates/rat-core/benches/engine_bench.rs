use criterion::{criterion_group, criterion_main, Criterion};
use rat_core::{AppConnection, AppIdentity, Lifetime, Rule, RuleEngine, Verdict};
use rat_types::Protocol;
use std::hint::black_box;
use uuid::Uuid;

fn generate_rules(count: usize) -> Vec<Rule> {
    let mut rules = Vec::with_capacity(count);
    for i in 0..count {
        let r = Rule {
            id: Uuid::new_v4(),
            verdict: if i % 2 == 0 {
                Verdict::Allow
            } else {
                Verdict::Deny
            },
            process_path: Some(format!("/usr/bin/app{}", i)),
            signing_id: None,
            team_id: None,
            remote_domain: Some(format!("example{}.com", i)),
            remote_host: None,
            remote_address: None,
            ports: None,
            proto: Some(Protocol::Tcp),
            enabled: true,
            approved: true,
            lifetime: Lifetime::Forever,
            profile_id: None,
            group_id: None,
            created_at: chrono::Utc::now(),
            note: None,
        };
        rules.push(r);
    }

    // Add one guaranteed matching rule at the end but with specific criteria
    let mut matching_rule = rules[0].clone();
    matching_rule.id = Uuid::new_v4();
    matching_rule.process_path = Some("/usr/bin/target_app".to_string());
    matching_rule.remote_domain = Some("target.com".to_string());
    rules.push(matching_rule);

    rules
}

fn bench_evaluation(c: &mut Criterion) {
    let rules = generate_rules(5000);
    let engine = RuleEngine::with_rules(rules, Verdict::Ask);

    let process = AppIdentity::new(None, None, "/usr/bin/target_app".to_string());
    let conn = AppConnection::new(
        process,
        Some("target.com".to_string()),
        "1.2.3.4".to_string(),
        443,
        Protocol::Tcp,
    );

    c.bench_function("evaluate 5000 rules", |b| {
        b.iter(|| engine.evaluate(black_box(&conn)))
    });
}

criterion_group!(benches, bench_evaluation);
criterion_main!(benches);
